use crate::alloc::boxed::Box;
use crate::mechname::Mechname;
use crate::registry::{Mechanism, Side};

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};

use super::{client, server};

#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
/// Mechanism description for GSSAPI
///
/// See the [`oauthbearer`](super) module documentation for details and usage.
pub static GSSAPI: Mechanism = Mechanism {
    mechanism: Mechname::const_new(b"GSSAPI"),
    priority: 300,
    client: Some(|_sasl, _offered| Ok(Box::new(client::Gssapi::default()))),
    server: None,
    first: Side::Client,
};
