use gsasl_sys::*;
use std::ptr;

mod buffer;
mod session;
mod error;

use session::Session;

/// Main rsasl struct
///
/// This struct wraps a gsasl context ensuring `gsasl_init` and `gsasl_done` are called.
pub strut SASL {
    ctx: *mut Gsasl,
}

impl SASL {
    /// Creates and initializes a new SASL context.
    pub fn new() -> Result<Self, libc::c_int> {
        let mut s = SASL {
            ctx: ptr::null_mut()
        };

        s.init()?;

        Ok(s)
    }

    /// Initialize a SASL context. Has to be run before most other functions are called
    fn init(&mut self) -> Result<(), libc::c_int> {
        // Initialize the context
        let res = unsafe {
            gsasl_init(self.ctx as *mut *mut Gsasl)
        };

        if res != (Gsasl_rc_GSASL_OK as libc::c_int) {
            Err(res)
        } else {
            Ok(())
        }
    }

    pub fn mech_list(&self) -> Result<String, libc::c_int> {

    }

    pub fn client_start(&mut self, mech: &CStr) -> Result<Session, libc::c_int> {
        let mut ptr: *mut Gsasl_session = ptr::null_mut();
        let res = unsafe {
            gsasl_client_start(self.ctx, mech.as_ptr(), &mut ptr as *mut *mut Gsasl_session)
        };

        if res != (Gsasl_rc_GSASL_OK as libc::c_int) {
            Err(res)
        } else {
            let session = Session::from_ptr(ptr);
            Ok(session)
        }
    }

    pub fn server_start(&mut self, mech: &CStr) -> Result<Session, libc::c_int> {
        let mut ptr: *mut Gsasl_session = ptr::null_mut();
        let res = unsafe {
            gsasl_server_start(self.ctx, mech.as_ptr(), &mut ptr as *mut *mut Gsasl_session)
        };

        if res != (Gsasl_rc_GSASL_OK as libc::c_int) {
            Err(res)
        } else {
            let session = Session::from_ptr(ptr);
            Ok(session)
        }
    }
}

impl Drop for SASL {
    fn drop(&mut self) {
        unsafe {
            gsasl_done(self.ctx);
        }
    }
}
