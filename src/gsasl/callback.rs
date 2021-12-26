use ::libc;
use crate::gsasl::consts::Gsasl_property;
use crate::{GSASL_OK, Shared, SaslError, SessionData};
use crate::consts::GSASL_IO_ERROR;

pub unsafe fn gsasl_callback(_ctx: *mut Shared,
                             sctx: &mut SessionData,
                             prop: Gsasl_property)
 -> libc::c_int {
    (if let Err(e) = sctx.callback(prop) {
        match e {
            SaslError::Sasl(n) => n,
            SaslError::Io(_) => GSASL_IO_ERROR,
        }
    } else {
        GSASL_OK
    }) as libc::c_int
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
