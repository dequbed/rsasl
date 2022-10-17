use crate::alloc::boxed::Box;
use crate::mechname::Mechname;
use crate::registry::Mechanism;
use crate::session::Side;

use super::{client, server};

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static LOGIN: Mechanism = Mechanism {
    mechanism: Mechname::const_new(b"LOGIN"),
    priority: 200,
    client: Some(|_sasl| Ok(Box::new(client::Login::new()))),
    server: Some(|_sasl| Ok(Box::new(server::Login::new()))),
    first: Side::Server,
};
