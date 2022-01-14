use crate::{Mechanism, Mechname};
use crate::mechanisms::anonymous::{client, server};


#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static ANONYMOUS: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unchecked(b"ANONYMOUS"),
    priority: 100,
    client: Some(|_sasl| Ok(Box::new(client::Anonymous))),
    server: Some(|_sasl| Ok(Box::new(server::Anonymous)))
};