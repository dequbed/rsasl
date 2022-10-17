use crate::alloc::boxed::Box;
use crate::mechname::Mechname;
use crate::registry::{Matches, Mechanism, Named, Side};

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};

use super::{client, server};

#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
/// Mechanism description for PLAIN
///
/// See the [`plain`](super) module documentation for details and usage.
pub static XOAUTH2: Mechanism = Mechanism {
    mechanism: Mechname::const_new(b"XOAUTH2"),
    priority: 300,
    client: Some(|| Ok(Box::new(client::XOAuth2::default()))),
    server: Some(|_sasl| Ok(Box::new(server::XOAuth2::default()))),
    first: Side::Client,

    select: |_| Some(Matches::<Select>::name()),
    offer: |_| true,
};

struct Select;
impl Named for Select {
    fn mech() -> &'static Mechanism {
        &XOAUTH2
    }
}
