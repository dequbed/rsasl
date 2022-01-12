//! RSASL is a pure Rust SASL framework designed to make crates implementing SASL-authenticated
//! protocol not have to worry about SASL.
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
//! [`Session`] on how to perform the actual authentication exchange)
//!
//! In addition protocol implementations should add a dependency on rsasl like this:
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
//! TODO:
//!     - Static vs Dynamic Registry
//!     - Explicit dependency because feature unification
//!
//! ## Custom Mechanisms
//!
//! TODO:
//!     - Explain Upstream or separate crate
//!     - Explain registry_static / registry_dynamic features => what *must* mech crates export?
//!     - Steps to mechanism:
//!         0. Depend on rsasl with `custom_mechanism` feature
//!         1. Write impl MechanismBuilder & impl Mechanism
//!         2. Add to Registry
//!         3. Done?
//!

use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

pub use libc;

pub mod buffer;
pub mod session;
pub mod error;
pub mod callback;

mod gsasl;
pub mod mechanisms;
pub mod mechanism;
pub mod mechname;
pub mod registry;

pub mod validate;
pub mod property;

pub use property::{
    Property,
    PropertyDefinition,
    PropertyQ,
};
use crate::callback::Callback;
use crate::error::SASLError;
use crate::mechanism::{MechanismBuilder, MechanismInstance};
use crate::mechname::Mechname;
use crate::registry::{Mechanism, MECHANISMS_CLIENT, MECHANISMS_SERVER};
use crate::session::Session;


// SASL Provider:
// I'm a protocol and I need to do SASL
// 1. get sasl: &SASLProvider from $somewhere
// 2. Get list of supported via sasl.get_supported_mechs()
// 3. When offered more than one by a client/server, use sasl.suggest_(client|server)_mechanism()
// 4. call session = (sasl.client_start(MECHANISM) | sasl.server_start(MECHANISM))
// 5. call session.step(data, &mut out) or session.step64(data, &mut out) as needed.
// 6. ???
// 7. PROFIT!
// (TODO: How to handle EXTERNAL?)
// Bonus minus points: sasl.wrap(data) and sasl.unwrap(data) for security layers. Prefer to not
// and instead do TLS.

/// SASL Provider context
///
/// This is the central type required to use SASL both for protocol implementations requiring the
/// use of SASL and for users wanting to provide SASL authentication to such implementations.
///
/// This struct is not `Clone` or `Copy`, but all functions required for authentication exchanges
/// only need a non-mutable reference to it. If you need to do several authentication exchanges in
/// parallel, e.g. in a server context, you can wrap it in an [`std::sync::Arc`] to add cheap
/// cloning.
pub struct SASL {
    /// Global data that is valid irrespective of context, such as e.g. a OAuth2 callback url or
    /// a GSSAPI realm.
    /// Can also be used to store properties such as username and password
    pub global_data: Arc<HashMap<Property, Box<dyn Any>>>,
    pub callback: Option<Arc<dyn Callback>>,
}

impl SASL {
    pub fn new() -> Self {
        Self {
            global_data: Arc::new(HashMap::new()),
            callback: None,
        }
    }

    pub fn install_callback(&mut self, callback: Arc<dyn Callback>) {
        self.callback = Some(callback);
    }
}

impl Debug for SASL {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SASL")
            .field("global data", &self.global_data)
            .field("has callback", &self.callback.is_some())
            .finish()
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
    pub fn client_mech_list(&self) -> impl IntoIterator<Item=&Mechanism>
    {
        MECHANISMS_CLIENT.into_iter()
    }

    /// Returns the list of Server Mechanisms supported by this provider.
    ///
    /// An server allowing client software to "log in" would use this method. A client
    /// application would use [`SASL::client_mech_list()`].
    pub fn server_mech_list(&self) -> impl IntoIterator<Item=&Mechanism>
    {
        MECHANISMS_SERVER.iter()
    }

    /// Suggests a mechanism to use for client-side authentication, chosen from the given list of
    /// available mechanisms.
    /// If any passed mechanism names are invalid these are silently ignored.
    /// This method will return `None` if none of the given mechanisms are agreeable.
    pub fn suggest_client_mechanism<'a>(&self, mechs: impl IntoIterator<Item=&'a [u8]>)
        -> Option<&Mechanism>
    {
        None
    }

    /// Suggests a mechanism to use for server-side authentication, chosen from the given list of
    /// available mechanisms.
    /// If any passed mechanism names are invalid these are silently ignored.
    /// This will return `None` if none of the given mechanisms are agreeable.
    pub fn suggest_server_mechanism<'a>(&self, mechs: impl IntoIterator<Item=&'a [u8]>)
        -> Option<&Mechanism>
    {
        None
    }

    /// Returns whether there is client-side support for the given mechanism
    pub fn client_supports(&self, mech: &mechname::Mechname) -> bool {
        self.client_mech_list().into_iter().any(|supported|
            supported.mechanisms.iter().any(|name| *name == mech))
    }

    /// Returns whether there is server-side support for the specified mechanism
    pub fn server_supports(&self, mech: &mechname::Mechname) -> bool {
        self.server_mech_list().into_iter().any(|supported|
            supported.mechanisms.iter().any(|name| *name == mech))
    }

    /// Starts a authentication exchange as a client
    ///
    /// Depending on the mechanism chosen this may need additional data from the application, e.g.
    /// an authcid, optional authzid and password for PLAIN. To provide that data an application
    /// has to either call `set_property` before running the step that requires the data, or
    /// install a callback.
    pub fn client_start(&self, mech: &mechname::Mechname) -> Result<Session, SASLError> {
        let mut stored_name = None;
        for mechanism in self.client_mech_list() {
            if mechanism.mechanisms.iter().any(|name| {
                stored_name = Some(*name);
                *name == mech
            }) {
                let auth = (mechanism.start)(&self)?;
                return Ok(Session::new(self.callback.clone(),
                                       MechanismInstance { name: stored_name.unwrap(), inner: auth },
                                       self.global_data.clone()));
            }
        }

        let mut mechanism = [0u8; 20];
        let len = mech.as_bytes().len();
        (&mut mechanism[0..len]).copy_from_slice(mech.as_bytes());
        Err(SASLError::UnknownMechanism { mechanism, len })
    }

    /// Starts a authentication exchange as the server role
    ///
    /// An application acting as server will most likely need to implement a callback to check the
    /// authentication data provided by the user.
    ///
    /// See [Callback](Callback) on how to implement callbacks.
    pub fn server_start(&self, mech: &mechname::Mechname) -> Result<Session, SASLError> {
        let mut stored_name = None;
        for mechanism in self.server_mech_list() {
            if mechanism.mechanisms.iter().any(|name| {
                stored_name = Some(*name);
                *name == mech
            }) {
                let auth = (mechanism.start)(&self)?;
                return Ok(Session::new(self.callback.clone(),
                                       MechanismInstance { name: stored_name.unwrap(), inner: auth },
                                       self.global_data.clone()));
            }
        }

        let mut mechanism = [0u8; 20];
        let len = mech.as_bytes().len();
        (&mut mechanism[0..len]).copy_from_slice(mech.as_bytes());
        Err(SASLError::UnknownMechanism { mechanism, len })

    }
}

struct Shared;

// SASL Impl:
// I'm using a crate that wants me to do SASL
// 1. Construct a as global as possible SASLProvider with the mechanisms you want. Give it a
// custom priority list if you want.
// 2. Install a callback or provide required Property value beforehand (hey, you configured the
// list of mechanisms, you know what Properties will be required)
// 3. Pass this SASLProvider to the protocol handler
// 4. Expect callbacks if you didn't provide all Properties. Also expect callbacks if you're
// doing the server end of things

// SASL Mech:
// I need to add a Mechanism
// 1. init() -> Global constructor, called once per SASLProvider.
// 2. start() -> Instance initializer. validate that required things are present, construct a struct
//      impl Mechanism containing all state you'll carry around. This function is also used to check
//      if the current context can support your mechanism so don't do too volatile things.
// 3. step(input: Option<&[u8]>, output: impl Write) -> process input, write output, indicate new
//      state (containing how much you've written too!)
// 4. encode()/decode() security layer stuff. Please don't.