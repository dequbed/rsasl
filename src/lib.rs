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
//! [`Session::step64`] until [`State::Finished`] is returned.
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
//! The system to add custom mechanisms is in flux and does not observe the same stability
//! guarantees as the rest of the crate. Breaking changes in this system may happen even for
//! minor changes of the crate version.
//!

use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

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
mod mechanism;
mod registry;

mod channel_bindings;
mod context;
mod typed;

mod vectored_io;

pub use session::{Session, State};
pub use callback::SessionCallback;
pub use property::Property;

use crate::error::SASLError;
use crate::mechanism::Authentication;
use crate::mechname::Mechname;
use crate::registry::Mechanism;
use crate::session::{SessionBuilder, Side};

/// SASL Provider context
///
/// This is the central type required to use SASL both for protocol implementations requiring the
/// use of SASL and for users wanting to provide SASL authentication to such implementations.
///
/// This struct is neither `Clone` nor `Copy`, but all functions required for authentication
/// exchanges only need a non-mutable reference to it. If you want to be able to do several
/// authentication exchanges in parallel, e.g. in a server context, you can wrap it in an
/// [`std::sync::Arc`] to add cheap cloning, or initialize it as a global value.
pub struct SASL {
    pub callback: Arc<dyn SessionCallback>,

    #[cfg(feature = "registry_dynamic")]
    dynamic_mechs: Vec<&'static Mechanism>,
    #[cfg(feature = "registry_static")]
    static_mechs: &'static [Mechanism],

    sort_fn: fn(a: &&Mechanism, b: &&Mechanism) -> Ordering,
}

impl Debug for SASL {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SASL");
        #[cfg(feature = "registry_dynamic")]
        s.field("registered mechanisms", &self.dynamic_mechs);
        #[cfg(feature = "registry_static")]
        s.field("collected mechanisms", &self.static_mechs);
        s.finish()
    }
}

#[cfg(feature = "provider")]
/// ### Provider functions
///
/// These methods are only available when compiled with feature `provider`
/// or `provider_base64` (enabled by default).
/// They are mainly relevant for protocol implementations wanting to start an
/// authentication exchange.
impl SASL {
    /// Return all mechanisms supported on the client side by this provider.
    ///
    /// An interactive client "logging in" to some server application would use this method. The
    /// server application would use [`SASL::server_mech_list()`].
    pub fn client_mech_list(&self) -> impl IntoIterator<Item = &'static Mechanism> + '_ {
        #[cfg(feature = "registry_static")]
        {
            #[cfg(feature = "registry_dynamic")]
            {
                registry::MECHANISMS
                    .into_iter()
                    .chain(self.dynamic_mechs.iter().map(|m| *m))
                    .filter(|mechanism| mechanism.client.is_some())
            }
            #[cfg(not(feature = "registry_dynamic"))]
            {
                registry::MECHANISMS
                    .into_iter()
                    .filter(|mechanism| mechanism.client.is_some())
            }
        }
        #[cfg(all(not(feature = "registry_static"), feature = "registry_dynamic"))]
        {
            self.dynamic_mechs.iter().map(|m| *m)
        }
        #[cfg(not(any(feature = "registry_static", feature = "registry_dynamic")))]
        {
            []
        }
    }

    /// Return all mechanisms supported on the server side by this provider.
    ///
    /// An server allowing client software to "log in" would use this method. A client
    /// application would use [`SASL::client_mech_list()`].
    pub fn server_mech_list(&self) -> impl IntoIterator<Item = &'static Mechanism> + '_ {
        let statics = {
            #[cfg(feature = "registry_static")]
            {
                IntoIterator::into_iter(registry::MECHANISMS)
            }
            #[cfg(not(feature = "registry_static"))]
            {
                IntoIterator::into_iter([])
            }
        };
        let dynamics = {
            #[cfg(feature = "registry_dynamic")]
            {
                self.dynamic_mechs.iter().map(|m| *m)
            }
            #[cfg(not(feature = "registry_dynamic"))]
            {
                (&[]).iter()
            }
        };
        statics
            .chain(dynamics)
            .filter(|mechanism: &&Mechanism| mechanism.server.is_some())
    }

    // FIXME: There need to be two variants of this fn since we have to choose "-PLUS" here. So
    //        we need to be able to supply info of if we'll supply channel binding data already.
    //        (probably just supply the channel binding callback and good enough)
    pub fn client_start_suggested<'a>(
        &self,
        mechs: impl IntoIterator<Item = &'a Mechname>,
    ) -> Result<SessionBuilder, SASLError> {
        mechs
            .into_iter()
            .filter_map(|name| {
                self.client_mech_list().into_iter().find_map(|mech| {
                    if mech.mechanism == name {
                        mech.client(&self)
                            // Option<Result<Session, SASLError>> -> Option<(&Mechanism, Session)>
                            .map(|res| res.ok().map(|auth| (mech, auth)))
                            .flatten()
                    } else {
                        None
                    }
                })
            })
            .max_by(|(a, _), (b, _)| (self.sort_fn)(a, b))
            .map(|(m, auth)| self.new_session(m, auth, Side::Client))
            .ok_or(SASLError::NoSharedMechanism)
    }

    pub fn server_start_suggested<'a>(
        &self,
        mechs: impl IntoIterator<Item = &'a Mechname>,
    ) -> Result<SessionBuilder, SASLError> {
        mechs
            .into_iter()
            .filter_map(|name| {
                self.server_mech_list().into_iter().find_map(|mech| {
                    if mech.mechanism == name {
                        mech.server(&self)
                            .map(|res| res.ok().map(|auth| (mech, auth)))
                            .flatten()
                    } else {
                        None
                    }
                })
            })
            .max_by(|(a, _), (b, _)| (self.sort_fn)(a, b))
            .map(|(m, auth)| self.new_session(m, auth, Side::Server))
            .ok_or(SASLError::NoSharedMechanism)
    }

    /// Returns whether there is client-side support for the given mechanism.
    ///
    /// You should not call this function to filter supported mechanisms if you intend to start a
    /// session right away since this function only calls `self.client_start()` with the given
    /// Mechanism name and throws away the Session.
    fn client_supports(&self, mech: &mechname::Mechname) -> bool {
        self.client_start(mech).is_ok()
    }

    /// Returns whether there is server-side support for the specified mechanism
    ///
    /// You should not call this function to filter supported mechanisms if you intend to start a
    /// session right away since this function only calls `self.server_start()` with the given
    /// Mechanism name and throws away the Session.
    fn server_supports(&self, mech: &mechname::Mechname) -> bool {
        self.server_start(mech).is_ok()
    }

    /// Start a new session with the given [`Authentication`] implementation
    ///
    /// This function should rarely be necessary, see [`SASL::client_start`] and
    /// [`SASL::server_start`] for more ergonomic alternatives.
    fn new_session(
        &self,
        mechdesc: &'static Mechanism,
        mechanism: Box<dyn Authentication>,
        side: Side,
    ) -> SessionBuilder {
        SessionBuilder::new(self.callback.clone(), mechanism, *mechdesc, side)
    }

    #[doc(hidden)]
    #[inline(always)]
    fn start_inner<'a>(
        &self,
        mech: &Mechname,
        mech_list: impl IntoIterator<Item = &'static Mechanism>,
        start: impl Fn(&Mechanism) -> Option<Result<Box<dyn Authentication>, SASLError>>,
        side: Side,
    ) -> Result<SessionBuilder, SASLError> {
        // Using an inverted result to shortcircuit out of `try_fold`: We want to stop looking
        // for mechanisms as soon as we found the first matching one. try_fold stop running as
        // soon as the first `ControlFlow::Break` is found, which for the implementation of `Try` on
        // `Result` is the first `Result::Err`.
        // If no break is encountered the `try_fold` will return `Ok(())` which we can then
        // interpret as this mechanism not being supported.
        let foldout = mech_list.into_iter().try_fold((), move |(), supported| {
            let opt = if supported.mechanism == mech {
                start(supported).map(|res| res.map(|auth| (supported, auth)))
            } else {
                None
            };
            match opt {
                Some(res) => Err(res),
                None => Ok(()),
            }
        });

        match foldout {
            Err(res) => Result::map(res, |(name, auth)| self.new_session(name, auth, side)),
            Ok(()) => Err(SASLError::unknown_mechanism(mech)),
        }
    }

    /// Starts a authentication exchange as a client
    ///
    /// Depending on the mechanism chosen this may need additional data from the application, e.g.
    /// an authcid, optional authzid and password for PLAIN. To provide that data an application
    /// has to either call `set_property` before running the step that requires the data, or
    /// install a callback.
    pub fn client_start(&self, mech: &mechname::Mechname) -> Result<SessionBuilder, SASLError> {
        self.start_inner(
            mech,
            self.client_mech_list(),
            |mechanism| mechanism.client(&self),
            Side::Client,
        )
    }

    /// Starts a authentication exchange as the server role
    ///
    /// An application acting as server will most likely need to implement a callback to check the
    /// authentication data provided by the user.
    ///
    /// See [SessionCallback] on how to implement callbacks.
    pub fn server_start(&self, mech: &mechname::Mechname) -> Result<SessionBuilder, SASLError> {
        self.start_inner(
            mech,
            self.server_mech_list(),
            |mechanism| mechanism.server(&self),
            Side::Server,
        )
    }
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
