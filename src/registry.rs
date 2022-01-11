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
//! pub static MYCOOLMECHANISM_CLIENT: Client = Client(Mechanism {
//!     matches: |name| name.as_str() == "X-MYCOOLMECHANISM",
//!     start: |_sasl| Box::new(MyCoolMechanism),
//! });
//! #[cfg_attr(feature = "rsasl/registry_static", distributed_slice(MECHANISMS_SERVER))]
//! pub static MYCOOLMECHANISM_SERVER: Server = Server(Mechanism {
//!     matches: |name| name.as_str() == "X-MYCOOLMECHANISM",
//!     start: |_sasl| Box::new(MyCoolMechanism),
//! });
//! ```
//!
//! Note: Due to [rustc issue #47384](https://github.com/rust-lang/rust/issues/47384) the static(s)
//! for your Mechanism MUST be marked `pub` and be reachable by dependent crates, otherwise they
//! may be silently dropped by the compiler.

use std::fmt::{Debug, Display, Formatter};
use crate::gsasl::consts::GSASL_OK;
use crate::{MechanismBuilder, SASL, SASLError};
use crate::gsasl::gsasl::MechanismVTable;
use crate::gsasl::init::register_builtin_mechs;
use crate::mechanism::Authentication;
use crate::mechname::Mechname;

#[cfg(feature = "registry_static")]
pub use registry_static::*;

#[derive(Copy, Clone)]
/// A struct describing a particular Mechanism
///
/// Every mechanism to be used with RSASL must define an instance of this struct for itself.
pub struct MechanismDescription {
    name: &'static str,

    /// This mechanism transfers (parts of) a client secret such as passwords in plain, so
    /// should only be used over trusted connections such as TLS-secured ones.
    plaintext: bool,

    /// This mechanism offers the potential of channel bindings.
    channel_bindings: bool,

    /// This mechanism offers the potential of mutual authentication, i.e. an attacker can not
    /// fake a successful authentication without knowing some secret data.
    mutual_authentication: bool,

    client: Option<&'static dyn MechanismBuilder>,
    server: Option<&'static dyn MechanismBuilder>,
}

impl MechanismDescription {
    pub fn new(name: &'static str,
                     plaintext: bool,
                     channel_bindings: bool,
                     mutual_authentication: bool,
                     client: Option<&'static dyn MechanismBuilder>,
                     server: Option<&'static dyn MechanismBuilder>
        ) -> MechanismDescription
    {
        Self { name, plaintext, channel_bindings, mutual_authentication, client, server }
    }
    pub fn name(&self) -> &Mechname {
        Mechname::new(self.name)
    }

    pub fn client(&self) -> Option<&dyn MechanismBuilder> {
        self.client
    }

    pub fn server(&self) -> Option<&dyn MechanismBuilder> {
        self.server
    }

    pub fn init(&mut self) {
        if let Some(c) = &self.client {
            c.init();
        }
        if let Some(s) = &self.server {
            s.init();
        }
    }
}

impl Debug for MechanismDescription {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MechanismDescription")
            .field("name", &self.name)
            .field("plaintext", &self.plaintext)
            .field("channel bindings", &self.channel_bindings)
            .field("mutual authentication", &self.mutual_authentication)
            .field("has client side", &self.client.is_some())
            .field("has server side", &self.server.is_some())
            .finish()
    }
}

pub struct Registry {
    registered: Vec<MechanismDescription>
}

impl Debug for Registry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
         .field("registered", &self.registered)
         .finish()
    }
}

impl Display for Registry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&Mechname> = self.registered.iter()
                                        .map(|m| m.name())
                                        .collect();
        f.debug_struct("Registry")
         .field("registered", &names)
         .finish()
    }
}

impl Registry {
    pub fn new(registered: Vec<MechanismDescription>) -> Self {
        Self {
            registered,
        }
    }

    pub fn client_mech_list(&self) -> impl Iterator<Item=(&Mechname, &dyn MechanismBuilder)>
    {
        self.registered.iter().filter_map(|m| {
            if let Some(client) = m.client() {
                Some((m.name(), client))
            } else {
                None
            }
        })
    }

    pub fn server_mech_list(&self) -> impl Iterator<Item=(&Mechname, &dyn MechanismBuilder)>
    {
        self.registered.iter().filter_map(|m| {
            if let Some(server) = m.server() {
                Some((m.name(), server))
            } else {
                None
            }
        })
    }

    pub fn suggest_client_mechanism<'a>(&self, proposed: impl Iterator<Item=&'a Mechname>)
        -> Option<(&'static Mechname, &'static dyn MechanismBuilder)>
    {
        None
    }

    pub fn suggest_server_mechanism<'a>(&self, proposed: impl Iterator<Item=&'a Mechname>)
        -> Option<(&'static Mechname, &'static dyn MechanismBuilder)>
    {
        None
        /*
        let mut min: Option<(usize, &mechname::Mechname)> = None;
        for mech in mechs {
            let mut name: &mechname::Mechname = mechname::Mechname::new("");
            if let Some(idx) = self.shared.mechs.iter().position(|supported| {
                name = supported.name();
                supported.name() == mech && supported.server().start(self).is_ok()
            }) {
                if min.is_none() || min.unwrap().0 > idx {
                    min = Some((idx, name));
                }
            }
        }

        min.map(|(_, mech)| mech)
         */
    }

    pub(crate) fn register_cmech(&mut self, name: &'static Mechname,
                          client: &'static MechanismVTable,
                          server: &'static MechanismVTable)
    {
        self.register(MechanismDescription::new(
            name,
            true,
            false,
            false,
            Some(client),
            Some(server),
        ));
    }

    pub fn register(&mut self, mut desc: MechanismDescription) {
        desc.init();
        self.registered.push(desc);
    }

    pub fn init_c(&mut self) -> Result<(), SASLError> {
        unsafe {
            let rc = register_builtin_mechs(self);
            if rc == GSASL_OK as libc::c_int {
                Ok(())
            } else {
                Err((rc as libc::c_uint).into())
            }
        }
    }
}

/// Mechanism Implementation
///
/// All mechanisms need to export a `static Mechanism` to be usable by rsasl, see the [module
/// documentation][crate::registry] for details.
pub struct Mechanism {
    /// Match function to indicate support for the given mechanism
    ///
    /// Usually an implementation only implements one specific mechanism, however in cases like
    /// `SCRAM-*` or `GS2-*` one implementation can be used for many different mechanisms.
    ///
    /// To simply match a specific Mechanism name pass a static closure:
    /// ```rust
    /// # use rsasl::mechname::Mechname;
    /// # use rsasl::registry::Mechanism;
    /// # let a = Mechanism {
    /// # start: |_sasl| unimplemented!(),
    /// matches: |name: &Mechname| name.as_str() == "X-MYCOOLMECHANISM"
    /// # };
    /// ```
    pub matches: fn (name: &Mechname) -> bool,

    /// Construct a new instance of this Mechanism
    pub start: fn (sasl: &SASL) -> Box<dyn Authentication>,
}

/// Client side of a Mechanism Implementation
pub struct Client(pub Mechanism);

pub struct Server(pub Mechanism);

#[cfg(feature = "registry_static")]
mod registry_static {
    pub use linkme::distributed_slice;
    use super::{Client, Server};

    #[distributed_slice]
    pub static MECHANISMS_CLIENT: [Client] = [..];

    #[distributed_slice]
    pub static MECHANISMS_SERVER: [Server] = [..];
}