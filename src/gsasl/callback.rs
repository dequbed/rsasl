use ::libc;
use crate::gsasl::consts::Gsasl_property;
use crate::{GSASL_OK, Shared, SessionData, SASLError};
use crate::consts::GSASL_IO_ERROR;

pub(crate) unsafe fn gsasl_callback(_ctx: *mut Shared,
                             sctx: &mut SessionData,
                             prop: Gsasl_property)
 -> libc::c_int {
    (if let Err(e) = sctx.callback(prop) {
        match e {
            SASLError::Gsasl(n) => n,
            _ => GSASL_IO_ERROR,
        }
    } else {
        GSASL_OK
    }) as libc::c_int
}
