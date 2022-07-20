//! Configuration supplied by the downstream user

use crate::builder::{ConfigBuilder, WantMechanisms};
use crate::callback::{Context, Request, SessionCallback};
use crate::registry::Mechanism;
use std::cmp::Ordering;
use std::fmt;
use std::marker::PhantomData;
use crate::error::{SASLError, SessionError};
use crate::property::{AuthId, AuthzId, Password};
use crate::session;
use crate::session::SessionData;

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

type FilterFn = fn(a: &&Mechanism) -> bool;
type SorterFn = fn(a: &&Mechanism, b: &&Mechanism) -> Ordering;


pub struct ClientSide {
    _marker: PhantomData<()>,
}

/// Configuration for a client-side SASL authentication
///
/// This is an easier to use type shortcut for the sided [`SASLConfig`] type.
pub struct ClientConfig;
impl ClientConfig {
    pub fn builder() -> ConfigBuilder<ClientSide, WantMechanisms> {
        ConfigBuilder::new(ClientSide { _marker: PhantomData })
    }

    /// Construct a SASLConfig with static credentials
    ///
    ///
    pub fn with_credentials(authzid: Option<String>, authid: String, password: String)
        -> Result<SASLConfig, SASLError>
    {
        let callback = CredentialsProvider {
            authid, password, authzid
        };
        Self::builder()
            .with_defaults()
            .with_callback(Box::new(callback), false)
    }
}

pub struct ServerSide {
    _marker: PhantomData<()>,
}

/// Configuration for a server-side SASL authentication
///
/// This is an easier to use type shortcut for the sided [`SASLConfig`] type.
pub struct ServerConfig {
    config: SASLConfig,
}

impl ServerConfig {
    pub fn builder() -> ConfigBuilder<ServerSide, WantMechanisms> {
        ConfigBuilder::new(ServerSide { _marker: PhantomData })
    }
    pub(crate) fn new(config: SASLConfig) -> Self {
        Self { config }
    }
}

/// Sided shareable configuration for a SASL provider
///
/// This type contains all user-specified configuration necessary for SASL authentication. It is
/// designed to be passed to a protocol implementation and provide an opaque and abstracted
/// interface to said configuration so that neither side has to expose implementation details.
///
/// A config is pinned to either the client or server side of an authentication, with the typedefs
/// [`ClientConfig`] and [`ServerConfig`] being provided as convenience shorthands.
pub struct SASLConfig {
    pub(crate) callback: Box<dyn SessionCallback>,

    pub(crate) filter: fn(a: &&Mechanism) -> bool,
    pub(crate) sorter: fn(a: &&Mechanism, b: &&Mechanism) -> Ordering,

    #[cfg(feature = "registry_dynamic")]
    dynamic_mechs: Vec<&'static Mechanism>,

    pub(crate) provides_channel_bindings: bool,
}
impl fmt::Debug for SASLConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("SASLConfig");
        d.field("static mechanisms", &crate::registry::MECHANISMS.as_ref());
        #[cfg(feature = "registry_dynamic")]
        d.field("dynamic mechanisms", &self.dynamic_mechs);
        d.finish()
    }
}

impl SASLConfig {
    #[cfg(not(feature = "registry_dynamic"))]
    pub(crate) fn new(
        callback: Box<dyn SessionCallback>,
        filter: FilterFn,
        sorter: SorterFn,
        provides_channel_bindings: bool,
    ) -> Result<Self, SASLError> {
        Ok(Self {
            side,
            callback,
            filter,
            sorter,
            provides_channel_bindings,
        })
    }
    #[cfg(feature = "registry_dynamic")]
    pub(crate) fn new(
        callback: Box<dyn SessionCallback>,
        filter: FilterFn,
        sorter: SorterFn,
        dynamic_mechs: Vec<&'static Mechanism>,
        provides_channel_bindings: bool,
    ) -> Result<Self, SASLError> {
        Ok(Self {
            callback,
            filter,
            sorter,
            dynamic_mechs,
            provides_channel_bindings,
        })
    }

    pub(crate) fn mech_list(&self) -> impl Iterator<Item = &Mechanism> {
        crate::registry::MECHANISMS.iter()
    }

    pub fn init(&mut self) {
        crate::init::register_builtin(self)
    }
}

/// A [`SessionCallback`] implementation returning preconfigured values
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
