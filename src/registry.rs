use crate::{CMechBuilder, GSASL_OK, MechanismBuilder, MechanismVTable, MechContainer, mechname, register_builtin_mechs, SASLError};
use crate::Mech;

pub(crate) trait Registry {
    fn find(&self, name: &str) -> Option<&dyn Mech>;

    fn suggest(&self, proposed: &[&str]) -> Option<&[&str]> {
        todo!()
    }
}

#[repr(transparent)]
#[derive(Debug)]
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
            client: CMechBuilder { vtable: client },
            server: CMechBuilder { vtable: server }
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