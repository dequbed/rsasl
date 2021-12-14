use ::libc;
use crate::gsasl::consts::{GSASL_NO_CALLBACK, Gsasl_property};
use crate::gsasl::gsasl::{Gsasl, Gsasl_callback_function, Gsasl_session};

pub unsafe fn gsasl_callback(mut ctx: *mut Gsasl,
                             sctx: *mut Gsasl_session,
                             prop: Gsasl_property)
 -> libc::c_int {
    todo!()
    /*
    if ctx.is_null() && sctx.is_null() {
        return GSASL_NO_CALLBACK as libc::c_int
    }
    if ctx.is_null() { ctx = (*sctx).ctx }
    if (*ctx).cb.is_some() {
        return (*ctx).cb.expect("non-null function pointer")(ctx, sctx, prop)
    }
    return GSASL_NO_CALLBACK as libc::c_int;
     */
}
