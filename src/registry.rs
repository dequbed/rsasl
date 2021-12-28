use std::fmt::{Debug, Formatter};
use crate::{CMechBuilder, GSASL_OK, MechanismVTable, MechContainer, mechname, register_builtin_mechs, SASLError};
use crate::Mech;
use crate::mechanism::MechanismBuilder;
use crate::registry::static_registry::StaticRegistry;

#[derive(Copy, Clone)]
/// A struct describing a particular Mechanism
///
/// Every mechanism to be used with RSASL must define an instance of this struct for itself.
pub struct MechanismDescription {
    pub name: &'static super::mechname::Mechanism,

    /// This mechanism transfers (parts of) a client secret such as passwords in plain, so
    /// should only be used over trusted connections such as TLS-secured ones.
    pub plaintext: bool,

    /// This mechanism offers the potential of channel bindings.
    pub channel_bindings: bool,

    /// This mechanism offers the potential of mutual authentication, i.e. an attacker can not
    /// fake a successful authentication without knowing some secret data.
    pub mutual_authentication: bool,

    pub builder: &'static dyn MechanismBuilder,
}

impl Debug for MechanismDescription {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MechanismDescription")
            .field("name", &self.name)
            .field("plaintext", &self.plaintext)
            .field("channel bindings", &self.channel_bindings)
            .field("mutual authentication", &self.mutual_authentication)
            .finish()
    }
}

#[cfg(any(feature = "registry_static"))]
mod static_registry {
    use std::fmt::{Display, Formatter};
    use crate::registry::MechanismDescription;
    inventory::collect!(MechanismDescription);

    #[repr(transparent)]
    #[derive(Clone, Debug)]
    pub(super) struct StaticRegistry {
        inner: Box<[&'static MechanismDescription]>,
    }

    impl StaticRegistry {
        pub fn new(inner: Box<[&'static MechanismDescription]>) -> Self {
            Self { inner }
        }

        pub fn with_filter<F: FnMut(&MechanismDescription) -> bool>(mut filter: F) -> Self {
            let inner = inventory::iter::<MechanismDescription>
                .into_iter()
                .filter(|m| filter(m))
                .collect();
            Self::new(inner)
        }

        pub fn with_all() -> Self {
            let inner = inventory::iter::<MechanismDescription>
                .into_iter()
                .collect();
            Self::new(inner)
        }
    }

    impl Default for StaticRegistry {
        fn default() -> Self {
            Self::with_all()
        }
    }

    impl Display for StaticRegistry {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            if f.alternate() {
                f.write_str("Enabled Mechanisms: \n")?;
                for m in self.inner.iter() {
                    writeln!(f, "\t - {}", m.name)?;
                }
                Ok(())
            } else {
                f.write_str("Enabled Mechanisms: [")?;
                for m in self.inner.iter() {
                    f.write_str(m.name)?;
                }
                f.write_str("]")
            }
        }
    }
}

pub(crate) struct Registry {
    #[cfg(any(feature = "registry_static"))]
    enabled_static: static_registry::StaticRegistry,
    #[cfg(any(feature = "registry_dynamic"))]
    mechs: Vec<Box<dyn Mech>>
}

impl Registry {
    pub fn new() -> Self {
        Self {
            #[cfg(any(feature = "registry_static"))]
            enabled_static: StaticRegistry::default(),
            #[cfg(any(feature = "registry_dynamic"))]
            mechs: Vec::new(),
        }
    }
}

#[cfg(any(feature = "registry_dynamic"))]
impl Registry {
    pub fn register_cmech(&mut self, name: &'static mechname::Mechanism,
                          client: MechanismVTable,
                          server: MechanismVTable)
    {
        let mut mech = MechContainer {
            name,
            client: CMechBuilder { name, vtable: client },
            server: CMechBuilder { name, vtable: server }
        };
        mech.init();
        self.mechs.push(Box::new(mech));
    }

    pub fn register<C: 'static + MechanismBuilder, S: 'static + MechanismBuilder>(
        &mut self,
        name: &'static mechname::Mechanism,
        client: C,
        server: S)
    {
        let mut mech = Box::new(MechContainer { name, client, server });
        mech.init();
        self.mechs.push(mech);
    }

    pub fn init() -> Result<Self, SASLError> {
        let mut this = Self::new();

        unsafe {
            let rc = register_builtin_mechs(&mut this);
            if rc == GSASL_OK as libc::c_int {
                Ok(this)
            } else {
                Err((rc as libc::c_uint).into())
            }
        }
    }
}

#[cfg(not(any(feature = "registry_dynamic")))]
impl Registry {
    pub fn init() -> Result<Self, SASLError> {
        Ok(Self::new())
    }
}