use std::fmt::Debug;
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

#[cfg(any(feature = "registry_static"))]
mod static_registry {
    use crate::registry::MechanismDescription;
    inventory::collect!(MechanismDescription);

    #[repr(transparent)]
    #[derive(Clone)]
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
}
#[cfg(not(any(feature = "registry_static")))]
mod static_registry {
    #[repr(transparent)]
    #[derive(Clone)]
    pub(super) struct StaticRegistry;

    impl Default for StaticRegistry {
        fn default() -> Self { Self }
    }
}

pub(crate) struct Registry {
    enabled_static: static_registry::StaticRegistry,
    mechs: Vec<Box<dyn Mech>>
}

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

    pub fn new() -> Result<Self, SASLError> {
        let mut this = Self {
            #[cfg(any(feature = "registry_static"))]
            enabled_static: StaticRegistry::default(),
            mechs: Vec::new(),
        };

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