//! Mechanism registry *only available with feature `unstable_custom_mechanism`*
//!
//! The Registry allows users to configure which mechanisms are enabled and their order of
//! importance.
//! By default the registry will collect and enable all known Mechanisms. It will prefer external
//! (i.e. coming from 3rd party downstream crates) Mechanisms over the built-in ones and prefers
//! built-in ones roughly by their cryptographic strength, preferring SSO-enabled mechanism.
//! An exception is made for DIGEST_MD5 and CRAM_MD5 which are always given the least priority.
//!
//! So the rough default priority goes:
//! - OPENID20, SAML20, GS2-*, GSSAPI
//! - SCRAM-SHA-256(-PLUS)
//! - SCRAM-SHA-1(-PLUS)
//! - PLAIN, SECURID
//! - LOGIN
//! - ANONYMOUS, EXTERNAL
//! - CRAM_MD5, DIGEST_MD5
//!
//! ## Static compile-time registry using dtolnay's `linkme` crate
//!
// TODO: Explain static registry
//!
//! Note: Due to [rustc issue #47384](https://github.com/rust-lang/rust/issues/47384) the static(s)
//! for your Mechanism MUST be marked `pub` and be reachable by dependent crates, otherwise they
//! may be silently dropped by the compiler.

use crate::alloc::boxed::Box;
use crate::mechanism::Authentication;
use crate::mechname::Mechname;
use core::fmt;

use crate::config::SASLConfig;
use crate::error::SASLError;
pub use crate::session::Side;
#[cfg(feature = "registry_static")]
pub use registry_static::*;

pub type StartFn =
    fn(sasl: &SASLConfig, offered: &[&Mechname]) -> Result<Box<dyn Authentication>, SASLError>;
pub type ServerStartFn = fn(sasl: &SASLConfig) -> Result<Box<dyn Authentication>, SASLError>;

#[derive(Copy, Clone)]
/// Mechanism Implementation
///
/// All mechanisms need to export a `static Mechanism` to be usable by rsasl, see the
/// [registry module documentation][crate::registry] for details.
pub struct Mechanism {
    /// The Mechanism served by this implementation.
    pub mechanism: &'static Mechname,

    pub(crate) priority: usize,

    pub(crate) client: Option<StartFn>,
    pub(crate) server: Option<ServerStartFn>,

    pub(crate) first: Side,
}
#[cfg(feature = "unstable_custom_mechanism")]
impl Mechanism {
    pub const fn build(
        mechanism: &'static Mechname,
        priority: usize,
        client: Option<StartFn>,
        server: Option<ServerStartFn>,
        first: Side,
    ) -> Self {
        Self {
            mechanism,
            priority,
            client,
            server,
            first,
        }
    }
}

impl Mechanism {
    pub fn client(
        &self,
        sasl: &SASLConfig,
        offered: &[&Mechname],
    ) -> Option<Result<Box<dyn Authentication>, SASLError>> {
        self.client.map(|f| f(sasl, offered))
    }

    pub fn server(&self, sasl: &SASLConfig) -> Option<Result<Box<dyn Authentication>, SASLError>> {
        self.server.map(|f| f(sasl))
    }
}

impl fmt::Debug for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mechanism")
            .field("name", &self.mechanism)
            .field("has client", &self.client.is_some())
            .field("has server", &self.server.is_some())
            .finish()
    }
}

impl fmt::Display for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.mechanism.as_str())
    }
}

#[derive(Debug, Clone)]
/// Registry of available mechanism implementations
///
/// This struct provides a common interface by abstracting the various ways mechanisms may be
/// registered.
pub struct Registry {
    static_mechanisms: &'static [Mechanism],
}

#[cfg(feature = "config_builder")]
impl Registry {
    #[inline(always)]
    /// Construct a registry with the given set of mechanisms, overwriting the default set.
    pub fn with_mechanisms(mechanisms: &'static [Mechanism]) -> Self {
        Self {
            static_mechanisms: mechanisms,
        }
    }

    pub(crate) fn credentials() -> Self {
        static MECHS: &[Mechanism] = &[
            #[cfg(feature = "plain")]
            crate::mechanisms::plain::PLAIN,
            #[cfg(feature = "login")]
            crate::mechanisms::login::LOGIN,
            #[cfg(feature = "scram-sha-1")]
            crate::mechanisms::scram::SCRAM_SHA1,
            #[cfg(feature = "scram-sha-2")]
            crate::mechanisms::scram::SCRAM_SHA256,
        ];
        Self::with_mechanisms(MECHS)
    }
}

pub(crate) type MechanismIter<'a> = core::slice::Iter<'a, Mechanism>;
impl Registry {
    #[inline(always)]
    pub(crate) fn get_mechanisms<'a>(&self) -> MechanismIter<'a> {
        self.static_mechanisms.iter()
    }
}

#[cfg(feature = "config_builder")]
impl Default for Registry {
    fn default() -> Self {
        Registry::with_mechanisms(&registry_static::MECHANISMS)
    }
}

#[cfg(feature = "registry_static")]
mod registry_static {
    use super::Mechanism;
    pub use linkme::distributed_slice;

    #[distributed_slice]
    pub static MECHANISMS: [Mechanism] = [..];
}
#[cfg(not(feature = "registry_static"))]
mod registry_static {
    use super::Mechanism;
    pub static MECHANISMS: [Mechanism; 0] = [];
}
