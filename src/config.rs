//! Configuration supplied by the downstream user

use crate::callback::{Context, Request, SessionCallback};
use crate::registry::{Mechanism, Registry};
use std::cmp::Ordering;
use std::fmt;
use std::marker::PhantomData;
use crate::error::{SASLError, SessionError};
use crate::property::{AuthId, AuthzId, Password};
use crate::session;
use crate::session::SessionData;

#[cfg(feature = "config_builder")]
pub use crate::builder::ConfigBuilder;

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::ClientSide {}
    impl Sealed for super::ServerSide {}
}
pub trait ConfigSide: sealed::Sealed {
    const SIDE: session::Side;
}

impl ConfigSide for ClientSide {
    const SIDE: session::Side = session::Side::Client;
}
impl ConfigSide for ServerSide {
    const SIDE: session::Side = session::Side::Server;
}

pub(crate) type FilterFn = fn(a: &Mechanism) -> bool;
pub(crate) type SorterFn = fn(a: &Mechanism, b: &Mechanism) -> Ordering;


pub struct ClientSide {
    _marker: PhantomData<()>,
}

/// Configuration for a client-side SASL authentication
///
/// This is an easier to use type shortcut for the sided [`SASLConfig`] type.
pub struct ClientConfig;
#[cfg(feature = "config_builder")]
impl ClientConfig {
    pub fn builder() -> ConfigBuilder<ClientSide, crate::builder::WantMechanisms> {
        ConfigBuilder::new(ClientSide { _marker: PhantomData })
    }

    /// Construct a SASLConfig with static credentials
    ///
    ///
    pub fn with_credentials(authzid: Option<String>, authid: String, password: String)
        -> Result<SASLConfig, SASLError>
    {
        struct CredentialsProvider {
            authid: String,
            password: String,
            authzid: Option<String>,
        }
        impl SessionCallback for CredentialsProvider {
            fn callback(
                &self,
                _session_data: &SessionData,
                _context: &Context,
                request: &mut Request<'_>,
            ) -> Result<(), SessionError> {
                request
                    .satisfy::<AuthId>(self.authid.as_str())?
                    .satisfy::<Password>(self.password.as_bytes())?;
                if let Some(authzid) = self.authzid.as_deref() {
                    request.satisfy::<AuthzId>(authzid)?;
                }
                Ok(())
            }
        }

        let callback = CredentialsProvider {
            authid, password, authzid
        };

        Self::builder()
            .with_default_mechanisms()
            .with_filter(|mechanism| {
                let name = mechanism.mechanism;
                match name.as_str() {
                    "PLAIN" | "LOGIN" => true,
                    n if n.starts_with("SCRAM-") => true,
                    _ => false,
                }
            })
            .with_default_sorting()
            .with_callback(Box::new(callback))
    }
}

pub struct ServerSide {
    _marker: PhantomData<()>,
}

/// Configuration for a server-side SASL authentication
///
/// This is an easier to use type shortcut for the sided [`SASLConfig`] type.
pub struct ServerConfig;

#[cfg(feature = "config_builder")]
impl ServerConfig {
    pub fn builder() -> ConfigBuilder<ServerSide, crate::builder::WantMechanisms> {
        ConfigBuilder::new(ServerSide { _marker: PhantomData })
    }
}

/// Sided shareable configuration for a SASL provider
///
/// This type contains all user-specified configuration necessary for SASL authentication. It is
/// designed to be passed to a protocol implementation and provide an opaque and abstracted
/// interface to said configuration so that neither side has to expose implementation details.
///
/// This type is constructed using the [`ClientConfig`] and [`ServerConfig`] helpers
pub struct SASLConfig {
    pub(crate) callback: Box<dyn SessionCallback>,

    pub(crate) filter: Option<FilterFn>,
    pub(crate) sorter: SorterFn,

    mechanisms: Registry,
}
impl fmt::Debug for SASLConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SASLConfig")
            .field("mechanisms", &self.mechanisms)
            .finish()
    }
}

impl SASLConfig {
    pub fn mech_list(&self) -> impl Iterator<Item=&Mechanism> {
        self.mechanisms.get_mechanisms()
    }
}

#[cfg(feature = "config_builder")]
impl SASLConfig {
    pub(crate) fn new(
        callback: Box<dyn SessionCallback>,
        filter: Option<FilterFn>,
        sorter: SorterFn,
        mechanisms: Registry,
    ) -> Result<Self, SASLError> {
        Ok(Self {
            callback,
            filter,
            sorter,
            mechanisms,
        })
    }
}

impl SASLConfig {
    #[cfg(any(feature = "registry_dynamic", feature = "registry_static"))]
    /// Register the builtin mechanisms
    ///
    /// When `registry_static` is used this is a no-op and does not need to be called.
    /// When `registry_dynamic` is used this will register all built-in mechanisms via the dynamic
    /// registry.
    ///
    /// This method mainly exists as a workaround to
    /// [rustc#47384](https://github.com/rust-lang/rust/issues/47384), which was fixed in rustc 1.62
    pub fn register_builtin(&mut self) {
        crate::init::register_builtin(self)
    }

    #[cfg(feature = "registry_dynamic")]
    /// Register a mechanism
    pub fn register(&mut self, mechanism: &'static Mechanism) {
        self.mechanisms.register(mechanism)
    }
}
