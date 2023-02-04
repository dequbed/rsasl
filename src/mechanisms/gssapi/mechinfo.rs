use crate::alloc::boxed::Box;
use crate::mechname::Mechname;
use crate::registry::{Matches, Mechanism, Named, Side};

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};

use super::{client, server};

#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
/// Mechanism description for GSSAPI
///
/// See the [`gssapi`](super) module documentation for details and usage.
pub static GSSAPI: Mechanism = Mechanism {
    mechanism: Mechname::const_new(b"GSSAPI"),
    priority: 300,
    client: Some(|| Ok(Box::new(client::Gssapi::default()))),
    server: Some(|_sasl| Ok(Box::new(server::Gssapi::default()))),
    first: Side::Client,

    select: |_| Some(Matches::<Select>::name()),
    offer: |_| true,
};

struct Select;
impl Named for Select {
    fn mech() -> &'static Mechanism {
        &GSSAPI
    }
}
