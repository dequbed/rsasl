use crate::{Mechanism, Mechname};
use crate::mechanisms::anonymous::{client, server};

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS_CLIENT};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS_CLIENT))]
pub static ANONYMOUS: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unchecked("ANONYMOUS"),
    client: Some(|_sasl| Ok(Box::new(client::Anonymous))),
    server: Some(|_sasl| Ok(Box::new(server::Anonymous)))
};
