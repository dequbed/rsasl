use ::libc;
use libc::size_t;
use crate::consts::GSASL_OK;
use crate::Shared;
use crate::gsasl::gsasl::{Gsasl_mechanism};

pub unsafe fn gsasl_register(
    ctx: &mut Shared,
    mech: &Gsasl_mechanism,
) -> libc::c_int
{
    ctx.register_cmech(mech.name, mech.client, mech.server);
    return GSASL_OK as libc::c_int;
}
