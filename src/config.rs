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
pub type ClientConfig = SASLConfig<ClientSide>;

pub struct ServerSide {
    _marker: PhantomData<()>,
}

/// Configuration for a server-side SASL authentication
///
/// This is an easier to use type shortcut for the sided [`SASLConfig`] type.
pub type ServerConfig = SASLConfig<ServerSide>;

/// Sided shareable configuration for a SASL provider
///
/// This type contains all user-specified configuration necessary for SASL authentication. It is
/// designed to be passed to a protocol implementation and provide an opaque and abstracted
/// interface to said configuration so that neither side has to expose implementation details.
///
/// A config is pinned to either the client or server side of an authentication, with the typedefs
/// [`ClientConfig`] and [`ServerConfig`] being provided as convenience shorthands.
pub struct SASLConfig<Side: ConfigSide> {
    side: Side,
    pub(crate) callback: Box<dyn SessionCallback>,

    filter: fn(a: &&Mechanism) -> bool,
    sorter: fn(a: &&Mechanism, b: &&Mechanism) -> Ordering,

    #[cfg(feature = "registry_dynamic")]
    dynamic_mechs: Vec<&'static Mechanism>,
}
impl<Side: ConfigSide> fmt::Debug for SASLConfig<Side> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("SASLConfig");
        #[cfg(feature = "registry_dynamic")]
        d.field("dynamic mechanisms", &self.dynamic_mechs);
        d.finish()
    }
}

impl SASLConfig<ClientSide> {
    pub fn builder() -> ConfigBuilder<ClientSide, WantMechanisms> {
        ConfigBuilder::new(ClientSide { _marker: PhantomData })
    }

    /// Construct a SASLConfig with static credentials
    ///
    ///
    pub fn with_credentials(authzid: Option<String>, authid: String, password: String)
        -> Result<Self, SASLError>
    {
        let callback = CredentialsProvider {
            authid, password, authzid
        };
        Self::builder()
            .with_defaults()
            .with_callback(Box::new(callback))
    }
}
impl SASLConfig<ServerSide> {
    pub fn builder() -> ConfigBuilder<ServerSide, WantMechanisms> {
        ConfigBuilder::new(ServerSide { _marker: PhantomData })
    }
}
impl<Side: ConfigSide> SASLConfig<Side> {
    #[cfg(not(feature = "registry_dynamic"))]
    pub(crate) fn new(
        side: Side,
        callback: Box<dyn SessionCallback>,
        filter: FilterFn,
        sorter: SorterFn,
    ) -> Result<Self, SASLError> {
        Ok(Self {
            side,
            callback,
            filter,
            sorter,
        })
    }
    #[cfg(feature = "registry_dynamic")]
    pub(crate) fn new(
        side: Side,
        callback: Box<dyn SessionCallback>,
        filter: FilterFn,
        sorter: SorterFn,
        dynamic_mechs: Vec<&'static Mechanism>,
    ) -> Result<Self, SASLError> {
        Ok(Self {
            side,
            callback,
            filter,
            sorter,
            dynamic_mechs,
        })
    }

    fn mech_list(&self) -> impl Iterator<Item = &Mechanism> {
        [].iter()
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
