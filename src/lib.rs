use gsasl_sys::*;
use std::ptr;
use std::ffi::CStr;
use std::ffi::CString;

mod buffer;
mod session;
mod error;

use session::Session;
use buffer::{SaslBuffer, SaslString};

/// Main rsasl struct
///
/// This struct wraps a gsasl context ensuring `gsasl_init` and `gsasl_done` are called.
pub struct SASL {
    ctx: *mut Gsasl,
}

impl SASL {
    /// Creates and initializes a new SASL context.
    pub fn new() -> error::Result<Self> {
        let mut s = SASL {
            ctx: ptr::null_mut()
        };

        s.init()?;

        Ok(s)
    }

    /// Initialize a SASL context. Has to be run before most other functions are called
    fn init(&mut self) -> error::Result<()> {
        // Initialize the context
        let res = unsafe {
            gsasl_init(self.ctx as *mut *mut Gsasl)
        };

        if res != (Gsasl_rc_GSASL_OK as libc::c_int) {
            Err(error::SaslError(res))
        } else {
            Ok(())
        }
    }

    /// return the list of supported mechanism on the client side as a space-separated string
    // The underlying pointer must be freed by the caller, so for the sake of easier ownership
    // this must return a SaslString and not a &str, &CStr or similar.
    pub fn client_mech_list(&self) -> error::Result<SaslString> {
        let mut out = ptr::null_mut();
        let ret = unsafe { gsasl_client_mechlist(self.ctx, &mut out as *mut *mut libc::c_char) };
        if ret != (Gsasl_rc_GSASL_OK as libc::c_int) {
            Err(error::SaslError(ret))
        } else {
            // If libgsasl does not return an error we can assume that out has been filled with
            // valid data.
            Ok(SaslString::from_raw(out))
        }
    }

    pub fn client_start(&mut self, mech: &CStr) -> error::Result<Session> {
        let mut ptr: *mut Gsasl_session = ptr::null_mut();
        let res = unsafe {
            gsasl_client_start(self.ctx, mech.as_ptr(), &mut ptr as *mut *mut Gsasl_session)
        };

        if res != (Gsasl_rc_GSASL_OK as libc::c_int) {
            Err(error::SaslError(res))
        } else {
            let session = Session::from_ptr(ptr);
            Ok(session)
        }
    }

    pub fn server_start(&mut self, mech: &CStr) -> error::Result<Session> {
        let mut ptr: *mut Gsasl_session = ptr::null_mut();
        let res = unsafe {
            gsasl_server_start(self.ctx, mech.as_ptr(), &mut ptr as *mut *mut Gsasl_session)
        };

        if res != (Gsasl_rc_GSASL_OK as libc::c_int) {
            Err(error::SaslError(res))
        } else {
            let session = Session::from_ptr(ptr);
            Ok(session)
        }
    }
}

impl Drop for SASL {
    fn drop(&mut self) {
        unsafe {
            // Finalize the context when its definitely not needed any more.
            // This function can handle NULL-pointers which happen should libgsasl fail to
            // initialize.
            gsasl_done(self.ctx);
        }
    }
}
