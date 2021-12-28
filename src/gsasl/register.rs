use ::libc;
use libc::size_t;
use crate::consts::GSASL_OK;
use crate::gsasl::gsasl::{Gsasl_mechanism};
use crate::registry::Registry;

pub(crate) unsafe fn gsasl_register(
    ctx: &mut Registry,
    mech: &'static Gsasl_mechanism,
) -> libc::c_int
{
    let name = crate::mechname::Mechname::new(mech.name);
    ctx.register_cmech(name, &mech.client, &mech.server);
    return GSASL_OK as libc::c_int;
}
