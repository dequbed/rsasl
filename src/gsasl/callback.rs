use ::libc;
use crate::gsasl::consts::Gsasl_property;
use crate::{SASL, Session};

pub unsafe fn gsasl_callback(_ctx: *mut SASL,
                             _sctx: &mut Session,
                             _prop: Gsasl_property)
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
