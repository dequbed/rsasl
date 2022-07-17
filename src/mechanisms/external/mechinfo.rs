use crate::mechanisms::external::{client, server};
use crate::mechname::Mechname;
use crate::registry::Mechanism;
use crate::session::Side;

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static EXTERNAL: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unvalidated(b"EXTERNAL"),
    priority: 100,
    client: Some(|_sasl| Ok(Box::new(client::External))),
    server: Some(|_sasl| Ok(Box::new(server::External))),
    first: Side::Client,
};
