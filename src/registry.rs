//! # Mechanism registry
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
//! When compiled with the `registry_static` feature flag rsasl has a static registry collecting
//! all available mechanisms at linking time. To submit a crate you need to define a pub `static`
//! [`MechanismClient`] and/or [`MechanismServer`] that are annotated with the
//! [`distributed_slice`] proc-macro (re-exported from `linkme` by this module):
//!
//! ```rust
//! # use std::io::Write;
//! # use rsasl::mechanism::Authentication;
//! # use rsasl::session::{SessionData, StepResult};
//!
//! // X-MYCOOLMECHANISM doesn't store any data between steps so it's an empty struct here
//! pub struct MyCoolMechanism;
//! impl Authentication for MyCoolMechanism {
//! # fn step(&mut self, session: &mut SessionData, input: Option<&[u8]>, writer: &mut dyn Write) -> StepResult {
//! #     unimplemented!()
//! # }
//! }
//!
//! use rsasl::registry::{
//!     Client,
//!     Server,
//!     Mechanism,
//! };
//!
//! // Since the static registry requires a feature flag, downstream crates should gate
//! // automatic registration the same way. Either by matching on `feature = "rsasl/registry_static"
//! // or by adding a feature flag that enables "rsasl/registry_static".
//! #[cfg(feature = "rsasl/registry_static")]
//! use rsasl::registry::{
//!     MECHANISMS_CLIENT,
//!     MECHANISMS_SERVER,
//!     distributed_slice,
//! };
//!
//! #[cfg_attr(feature = "rsasl/registry_static", distributed_slice(MECHANISMS_CLIENT))]
//! // It is *crucial* that these `static`s are marked `pub` and reachable by dependent crates, see
//! // the Note below.
//! pub static MYCOOLMECHANISM_CLIENT: Mechanism = Mechanism {
//!     mechanism: unsafe { Mechname::const_new_unchecked("X-MYCOOLMECHANISM") },
//!     client: Some(|_sasl| Ok(Box::new(MyCoolMechanism))),
//!     // In this case only the client side is implemented
//!     server: None,
//! };
//! ```
//!
//! Note: Due to [rustc issue #47384](https://github.com/rust-lang/rust/issues/47384) the static(s)
//! for your Mechanism MUST be marked `pub` and be reachable by dependent crates, otherwise they
//! may be silently dropped by the compiler.

use std::fmt::{Debug, Display, Formatter};
use crate::{SASL, SASLError};
use crate::mechanism::Authentication;
use crate::mechname::Mechname;

#[cfg(feature = "registry_static")]
pub use registry_static::*;

pub type MatchFn = fn (name: &Mechname) -> bool;
pub type StartFn = fn (sasl: &SASL) -> Result<Box<dyn Authentication>, SASLError>;

/// Mechanism Implementation
///
/// All mechanisms need to export a `static Mechanism` to be usable by rsasl, see the [module
/// documentation][crate::registry] for details.
pub struct Mechanism {
    /// The Mechanism served by this implementation.
    pub mechanism: &'static Mechname,

    /// Construct a new instance of this Mechanism
    pub client: Option<StartFn>,
    pub server: Option<StartFn>
}

impl Mechanism {
    pub fn client(&self, sasl: &SASL) -> Option<Result<Box<dyn Authentication>, SASLError>> {
       self.client.map(|f| f(sasl))
    }

    pub fn server(&self, sasl: &SASL) -> Option<Result<Box<dyn Authentication>, SASLError>> {
        self.server.map(|f| f(sasl))
    }
}

impl Debug for Mechanism {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mechanism")
            .field("name", &self.mechanism)
            .field("has client", &self.client.is_some())
            .field("has server", &self.server.is_some())
            .finish()
    }
}

impl Display for Mechanism {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.mechanism)
    }
}

#[cfg(feature = "registry_static")]
mod registry_static {
    pub use linkme::distributed_slice;
    use super::Mechanism;

    #[distributed_slice]
    pub static MECHANISMS: [Mechanism] = [..];
}