use ::libc;
use crate::gsasl::consts::GSASL_OK;
use crate::gsasl::gsasl::{Gsasl_mechanism};
use crate::SASL;

pub(crate) unsafe fn gsasl_register(
    ctx: &mut SASL,
    mech: &'static Gsasl_mechanism,
) -> libc::c_int
{
    let name = crate::mechname::Mechname::new_unchecked(mech.name);
    //ctx.register_cmech(name, &mech.client, &mech.server);
    return GSASL_OK as libc::c_int;
}

