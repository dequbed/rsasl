use crate::mechanisms::plain::{client, server};
use crate::mechname::Mechname;
use crate::registry::Mechanism;
use crate::session::Side;

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static PLAIN: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unvalidated(b"PLAIN"),
    priority: 300,
    client: Some(|_sasl, _offered| Ok(Box::new(client::Plain))),
    server: Some(|_sasl, _offered| Ok(Box::new(server::Plain))),
    first: Side::Client,
};
