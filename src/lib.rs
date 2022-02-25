#![allow(non_upper_case_globals, non_camel_case_types)]
//! RSASL is a pure Rust SASL framework designed to make supporting SASL in protocols, doing SASL
//! authentication in application code and adding new Mechanisms simple and safe.
//!
//! # Where to start
//! - [I'm implementing some network protocol and I need to add SASL authentication to it!](#protocol-implementations)
//! - [I'm an user of such a protocol crate and I need to configure my credentials!](#application-code)
//! - [I'm both/either/none of those but I have to implement a custom SASL mechanism!](#custom-mechanisms)
//!
//!
//! ## Protocol Implementations
//! Crates implementing a protocol should allow users to provide an [`SASL`] struct at run time.
//! Users construct this struct configuring the supported Mechanisms, their priorities and
//! providing all required information for the authentication exchange, such as username and
//! password.
//!
//! Protocol crates then call [`SASL::suggest_client_mechanism()`] or
//! [`SASL::suggest_server_mechanism()`] to decide on a common Mechanism based on user preference
//! and call [`SASL::client_start()`] or [`SASL::server_start()`] to actually start an
//! authentication exchange, returning a [`Session`] struct. (See the documentation for
//! [`Session`] on how to perform the steps of an authentication exchange)
//!
//! In addition protocol implementations should depend on rsasl like this:
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
//! to make rsasl a (nearly) zero-dependency crate and putting all decisions about compiled-in
//! support and features into the hand of the final user.
//! To this end a protocol crate **should not** re-export anything from the rsasl crate! Doing so
//! may lead to a situation where users can't use any mechanisms since they only depend on
//! rsasl via a transient dependency that has no mechanism features enabled.
//!
//! TODO: How to handle EXTERNAL?
//! TODO:
//!     Bonus minus points: sasl.wrap(data) and sasl.unwrap(data) for security layers. Prefer to
//!     not and instead do TLS. Needs better explanation I fear.
//!
//! ## Application Code
//!
//! Application code needs to construct a [`SASL`] struct that can then be passed to the protocol
//! handler to perform authentication exchanges. You need to provide this [`SASL`] struct with
//! either all required information such as username and password beforehand (this is usually
//! the best approach if you know all information beforehand) or by adding a [`Callback`] that
//! can request information piece by piece (this is the best approach if you have an interactive
//! client and want to be able to query your users or if you're implementing a server that has to
//! validate a provided password).
//!
//! Applications can explicitly enable and disable mechanism support using features, with the
//! default being to add all IANA-registered mechanisms.
//! See the module documentation for [`mechanisms`] for details.
//!
// TODO:
//     - Static vs Dynamic Registry
//     - Explicit dependency because feature unification
//!
//! ## Custom Mechanisms
//!
//! The system to add custom mechanisms is in flux and does not observe the same stability
//! guarantees as the rest of the crate. Breaking changes in this system may happen even for
//! minor changes of the crate version.
//!
// TODO:
//     - Explain Upstream or separate crate
//     - Explain registry_static / registry_dynamic features => what *must* mech crates export?
//     - Steps to mechanism:
//         0. Depend on rsasl with `custom_mechanism` feature
//         1. Write impl MechanismBuilder & impl Mechanism
//         2. Add to Registry
//         3. Done?

// SASL Mech:
// I need to add a Mechanism
// 1. init() -> Global constructor, called once per SASLProvider.
// 2. start() -> Instance initializer. validate that required things are present, construct a struct
//      impl Mechanism containing all state you'll carry around. This function is also used to check
//      if the current context can support your mechanism so don't do too volatile things.
// 3. step(input: Option<&[u8]>, output: impl Write) -> process input, write output, indicate new
//      state (containing how much you've written too!)
// 4. encode()/decode() security layer stuff. Please don't.

use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

pub use libc;

pub mod callback;
pub mod error;
pub mod sasl;
pub mod session;

mod gsasl;
pub mod init;
pub mod mechanism;
pub mod mechanisms;
pub mod mechname;
pub mod registry;

pub mod channel_bindings;
pub mod property;
pub mod validate;

mod vectored_io;

use crate::callback::Callback;
use crate::error::SASLError;
use crate::mechanism::Authentication;
use crate::mechname::Mechname;
use crate::registry::{Mechanism, MECHANISMS};
use crate::session::{Session, Side};
pub use property::{Property, PropertyQ};

/// SASL Provider context
///
/// This is the central type required to use SASL both for protocol implementations requiring the
/// use of SASL and for users wanting to provide SASL authentication to such implementations.
///
/// This struct is not `Clone` or `Copy`, but all functions required for authentication exchanges
/// only need a non-mutable reference to it. If you want to do several authentication exchanges in
/// parallel, e.g. in a server context, you can wrap it in an [`std::sync::Arc`] to add cheap
/// cloning.
pub struct SASL {
    pub callback: Option<Arc<dyn Callback>>,

    #[cfg(feature = "registry_dynamic")]
    dynamic_mechs: Vec<&'static Mechanism>,
    #[cfg(feature = "registry_static")]
    static_mechs: &'static [Mechanism],

    sort_fn: fn(a: &&Mechanism, b: &&Mechanism) -> Ordering,
}

impl Debug for SASL {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SASL");
        s.field("has callback", &self.callback.is_some());
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
    /// Returns the list of client mechanisms supported by this provider.
    ///
    /// An interactive client "logging in" to some server application would use this method. The
    /// server application would use [`SASL::server_mech_list()`].
    pub fn client_mech_list(&self) -> impl IntoIterator<Item = &'static Mechanism> + '_ {
        #[cfg(feature = "registry_static")]
        {
            #[cfg(feature = "registry_dynamic")]
            {
                MECHANISMS
                    .into_iter()
                    .chain(self.dynamic_mechs.iter().map(|m| *m))
                    .filter(|mechanism| mechanism.client.is_some())
            }
            #[cfg(not(feature = "registry_dynamic"))]
            {
                MECHANISMS
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

    /// Returns the list of Server Mechanisms supported by this provider.
    ///
    /// An server allowing client software to "log in" would use this method. A client
    /// application would use [`SASL::client_mech_list()`].
    pub fn server_mech_list(&self) -> impl IntoIterator<Item = &'static Mechanism> + '_ {
        let statics = {
            #[cfg(feature = "registry_static")]
            {
                MECHANISMS.into_iter()
            }
            #[cfg(not(feature = "registry_static"))]
            {
                [].into_iter()
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
            .filter(|mechanism| mechanism.server.is_some())
    }

    pub fn client_start_suggested<'a>(
        &self,
        mechs: impl IntoIterator<Item = &'a Mechname>,
    ) -> Result<Session, SASLError> {
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
    ) -> Result<Session, SASLError> {
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
    pub fn client_supports(&self, mech: &mechname::Mechname) -> bool {
        self.client_start(mech).is_ok()
    }

    /// Returns whether there is server-side support for the specified mechanism
    ///
    /// You should not call this function to filter supported mechanisms if you intend to start a
    /// session right away since this function only calls `self.server_start()` with the given
    /// Mechanism name and throws away the Session.
    pub fn server_supports(&self, mech: &mechname::Mechname) -> bool {
        self.server_start(mech).is_ok()
    }

    /// Start a new session with the given [`Authentication`] implementation
    ///
    /// This function should rarely be necessary, see [`SASL::client_start`] and
    /// [`SASL::server_start`] for more ergonomic alternatives.
    pub fn new_session(
        &self,
        mechdesc: &'static Mechanism,
        mechanism: Box<dyn Authentication>,
        side: Side,
    ) -> Session {
        Session::new(
            self.callback.clone(),
            mechdesc,
            mechanism,
            side,
        )
    }

    #[doc(hidden)]
    #[inline(always)]
    fn start_inner<'a>(
        &self,
        mech: &Mechname,
        mech_list: impl IntoIterator<Item = &'static Mechanism>,
        start: impl Fn(&Mechanism) -> Option<Result<Box<dyn Authentication>, SASLError>>,
        side: Side,
    ) -> Result<Session, SASLError> {
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
    pub fn client_start(&self, mech: &mechname::Mechname) -> Result<Session, SASLError> {
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
    /// See [Callback](Callback) on how to implement callbacks.
    pub fn server_start(&self, mech: &mechname::Mechname) -> Result<Session, SASLError> {
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
