use crate::mechanisms::anonymous::{client, server};
use crate::mechname::Mechname;
use crate::registry::Mechanism;
use crate::session::Side;

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};

#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static ANONYMOUS: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unvalidated(b"ANONYMOUS"),
    priority: 100,
    client: Some(|_sasl| Ok(Box::new(client::Anonymous))),
    server: Some(|_sasl| Ok(Box::new(server::Anonymous))),
    first: Side::Client,
};
