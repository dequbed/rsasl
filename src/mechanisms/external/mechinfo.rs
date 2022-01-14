use crate::{Mechanism, Mechname};
use crate::mechanisms::external::{client, server};

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static EXTERNAL: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unchecked(b"EXTERNAL"),
    client: Some(|_sasl| Ok(Box::new(client::External))),
    server: Some(|_sasl| Ok(Box::new(server::External)))
};
