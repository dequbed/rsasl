use std::fmt::{Debug, Display, Formatter};
use std::ptr::NonNull;
use crate::{GSASL_OK, MechanismVTable, MechContainer, mechname, register_builtin_mechs, SASL, SASLError};
use crate::Mech;
use crate::mechanism::{MechanismBuilder, MechanismInstance};
use crate::mechname::Mechname;

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

#[derive(Copy, Clone, Debug)]
/// Initializer for Mechanisms
///
/// This can't be const at the moment due to const fn not supporting pointer casting (required
/// for Mechname) and trait objects (required for the client/server fields).
///
/// When both are supported a registry could collect `&'static MechanismDescription` directly.
pub struct Initializer(pub fn() -> MechanismDescription);

pub(crate) struct Registry {
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

    pub fn register_cmech(&mut self, name: &'static mechname::Mechname,
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

impl Default for Registry {
    fn default() -> Self {
        #[cfg(feature = "registry_static")] {
            let mut this = Self::with_all();
            this.init_c();
            this
        }
        #[cfg(not(feature = "registry_static"))] {
            Self::new(Vec::new())
        }
    }
}

#[cfg(feature = "registry_static")]
pub mod static_registry {
    use std::fmt::{Debug, Display, Formatter};
    use crate::mechanism::MechanismBuilder;
    use crate::mechname::Mechname;
    use crate::Registry;
    use crate::registry::{Initializer, MechanismDescription};

    inventory::collect!(Initializer);

    impl Registry {
        pub fn with_filter<F: FnMut(&MechanismDescription) -> bool>(mut filter: F) -> Self {
            let inner = inventory::iter::<Initializer>
                .into_iter()
                .map(|f| (f.0)())
                .filter(|m| filter(m))
                .collect();
            Self::new(inner)
        }

        pub fn with_all() -> Self {
            let inner = inventory::iter::<Initializer>
                .into_iter()
                .map(|f| (f.0)())
                .collect();
            Self::new(inner)
        }
    }
}