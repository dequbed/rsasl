use crate::mechanisms::plain::{client, server};
use crate::{Mechanism, Mechname, Side};

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static PLAIN: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unvalidated(b"PLAIN"),
    priority: 300,
    client: Some(|_sasl| Ok(Box::new(client::Plain))),
    server: Some(|_sasl| Ok(Box::new(server::Plain))),
    first: Side::Client,
};
