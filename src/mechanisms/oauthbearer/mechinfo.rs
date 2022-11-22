use crate::alloc::boxed::Box;
use crate::mechname::Mechname;
use crate::registry::{Matches, Mechanism, Named, Side};

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};

use super::{client, server};

#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
/// Mechanism description for OAUTHBEARER
///
/// See the [`oauthbearer`](super) module documentation for details and usage.
pub static OAUTHBEARER: Mechanism = Mechanism {
    mechanism: Mechname::const_new(b"OAUTHBEARER"),
    priority: 300,
    client: Some(|| Ok(Box::new(client::OAuthBearer::default()))),
    server: Some(|_sasl| Ok(Box::new(server::OAuthBearer::default()))),
    first: Side::Client,

    select: |_| Some(Matches::<Select>::name()),
    offer: |_| true,
};

struct Select;
impl Named for Select {
    fn mech() -> &'static Mechanism {
        &OAUTHBEARER
    }
}
