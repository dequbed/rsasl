use std::fmt::Debug;
use crate::{CMechBuilder, GSASL_OK, MechanismVTable, MechContainer, mechname, register_builtin_mechs, SASLError};
use crate::Mech;
use crate::mechanism::MechanismBuilder;

pub struct StaticMechDescription {
    pub name: &'static super::mechname::Mechanism,
    pub builder: &'static dyn MechanismBuilder,
}

#[linkme::distributed_slice]
pub static MECHANISMS: [StaticMechDescription] = [..];

#[cfg(any(feature = "registry_static"))]
mod static_registry {
}

#[repr(transparent)]
pub(crate) struct DynamicRegistry {
    mechs: Vec<Box<dyn Mech>>
}

impl DynamicRegistry {
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