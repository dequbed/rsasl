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

use crate::mechanism::Authentication;
use crate::mechname::Mechname;
use std::fmt::{Debug, Display, Formatter};

#[cfg(feature = "registry_static")]
pub use registry_static::*;
use crate::config::{ClientSide, SASLConfig, ServerSide};
use crate::error::SASLError;
use crate::session::Side;

pub type MatchFn = fn(name: &Mechname) -> bool;

// FIXME: This *must* at some point get access to more context. Important is at least the
//        mechanism name. Required for GS2-* to figure out what GSSAPI mechanism to use. Nice to
//        have for SCRAM so that SHA-1, SHA-256, SHA-512 with -PLUS variant don't result in 6
//        separate registrations.
pub type StartFn<Side> = fn(sasl: &SASLConfig<Side>) -> Result<Box<dyn Authentication>, SASLError>;

#[derive(Copy, Clone)]
/// Mechanism Implementation
///
/// All mechanisms need to export a `static Mechanism` to be usable by rsasl, see the [module
/// documentation][crate::registry] for details.
pub struct Mechanism {
    /// The Mechanism served by this implementation.
    pub mechanism: &'static Mechname,

    pub priority: usize,

    pub client: Option<StartFn<ClientSide>>,
    pub server: Option<StartFn<ServerSide>>,

    pub first: Side,
}

pub struct MechanismSecurityFactors {
    /// Maximum possible Security Strength Factor (SSF) of the security layers installed
    ///
    /// SSF is a very fuzzy value but in general equates to the numbers of 'bits' of security,
    /// usually being linked to the key size. E.g. encryption using DES has `56`, 3DES `112`,
    /// AES128 `128`, and so on.
    /// Security layers that do not provide confidentiality (i.e. encryption) but integrity
    /// protection (via e.g. HMAC) usually have a SSF of 1.
    pub max_ssf: u16,

    /// This mechanism doesn't transfer secrets in plain text and is thus not susceptible to
    /// simple eavesdropping attacks.
    pub noplain: bool,
    /// This mechanism supports mutual authentication, i.e. if the authentication exchange
    /// succeeds then both the client and server have verified the identity of the other.
    pub mutual: bool,

    /// This mechanism can support channel bindings, i.e. cryptographically bind the
    /// authentication to the (encrypted) transport layer, usually TLS or IPsec.
    /// Using channel bindings can guard against some forms of man-in-the-middle attacks as the
    /// authentication will not succeed if both sides are not seeing the same cryptographic
    /// channel.
    ///
    /// Example: The TLS connection is being actively intercepted by an attacker that managed to
    /// get a trusted certificate deemed valid for the connection. Channel binding data for
    /// standard TLS cb mechanism includes either the public certificate that was used by the
    /// server or data derived from the (TLS) session secrets, both of which would show the
    /// MITM-attack in the above scenario.
    ///
    /// Channel binding *DOES NOT* guard against an attacker that has access to the channel secrets
    /// and can decrypt the channel passively.
    pub channel_binding: bool,
}

impl Mechanism {
    pub fn client(&self, sasl: &SASLConfig<ClientSide>) -> Option<Result<Box<dyn Authentication>, SASLError>> {
        self.client.map(|f| f(sasl))
    }

    pub fn server(&self, sasl: &SASLConfig<ServerSide>) -> Option<Result<Box<dyn Authentication>, SASLError>> {
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
        f.write_str(self.mechanism.as_str())
    }
}

#[cfg(feature = "registry_static")]
mod registry_static {
    use super::Mechanism;
    pub use linkme::distributed_slice;

    #[distributed_slice]
    pub static MECHANISMS: [Mechanism] = [..];
}
