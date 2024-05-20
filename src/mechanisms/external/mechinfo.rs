use crate::alloc::boxed::Box;
use crate::mechanisms::external::{client, server};
use crate::mechname::Mechname;
use crate::registry::{Matches, Mechanism, Named};
use crate::session::Side;

#[cfg_attr(
    feature = "registry_static",
    linkme::distributed_slice(crate::registry::MECHANISMS)
)]
pub static EXTERNAL: Mechanism = Mechanism {
    mechanism: Mechname::const_new(b"EXTERNAL"),
    priority: 100,
    client: Some(|| Ok(Box::new(client::External))),
    server: Some(|_sasl| Ok(Box::new(server::External))),
    first: Side::Client,

    select: |_| Some(Matches::<Select>::name()),
    offer: |_| true,
};

struct Select;
impl Named for Select {
    fn mech() -> &'static Mechanism {
        &EXTERNAL
    }
}
