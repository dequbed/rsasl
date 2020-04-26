use gsasl_sys::*;
use gsasl_sys::Gsasl_rc::*;
use std::ptr;
use std::ffi::CStr;

mod buffer;
mod session;
pub mod error;

use session::Session;
use buffer::SaslString;

pub use gsasl_sys::{
    Gsasl_rc as ReturnCode,
    Gsasl_property as Property,
};

pub use error::{
    SaslError,
    gsasl_err_to_str,
    gsasl_errname_to_str,
};

/// Main rsasl struct
///
/// This struct wraps a gsasl context ensuring `gsasl_init` and `gsasl_done` are called.
#[derive(Debug)]
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
            gsasl_init(&mut (self.ctx) as *mut *mut Gsasl)
        };

        if res != (GSASL_OK as libc::c_int) {
            Err(error::SaslError(res))
        } else {
            Ok(())
        }
    }

    /// return the list of supported mechanism on the client side as a space-separated string
    // The underlying pointer must be freed by the caller, so for the sake of easier ownership
    // this must return a SaslString and not a &str, &CStr or similar.
    pub fn client_mech_list(&self) -> error::Result<SaslString> {
        // rustc's borrow checker can't prove that we will never read this so this *must* be
        // initialized.
        let mut out = ptr::null_mut();

        // Call into libgsasl. As per usual ffi is unsafe
        let ret = unsafe { gsasl_client_mechlist(self.ctx, &mut out as *mut *mut libc::c_char) };

        // Take ownership of the output buffer so that it will always be freed and we don't leak
        // memory.
        let s = SaslString::from_raw(out);

        if ret != (GSASL_OK as libc::c_int) {
            // In the error case `s` will simply be dropped and freed.

            Err(error::SaslError(ret))
        } else {
            // If libgsasl does not return an error we can assume that out has been filled with
            // valid data.
            Ok(s)
        }
    }

    /// return the list of supported mechanism on the server side as a space-separated string
    // The underlying pointer must be freed by the caller, so for the sake of easier ownership
    // this must return a SaslString and not a &str, &CStr or similar.
    pub fn server_mech_list(&self) -> error::Result<SaslString> {
        // rustc's borrow checker can't prove that we will never read this so this *must* be
        // initialized.
        let mut out = ptr::null_mut();

        // Call into libgsasl. As per usual ffi is unsafe
        let ret = unsafe { gsasl_server_mechlist(self.ctx, &mut out as *mut *mut libc::c_char) };

        // Take ownership of the output buffer so that it will always be freed and we don't leak
        // memory.
        let s = SaslString::from_raw(out);

        if ret != (GSASL_OK as libc::c_int) {
            // In the error case `s` will simply be dropped and freed.

            Err(error::SaslError(ret))
        } else {
            // If libgsasl does not return an error we can assume that out has been filled with
            // valid string data.
            Ok(s)
        }
    }

    /// Decide wheter there is client-side support for the specified mechanism
    pub fn client_supports(&self, mech: &CStr) -> bool {
        // returns 1 if there is client support for the specific mechanism
        let ret = unsafe { gsasl_client_support_p(self.ctx, mech.as_ptr()) };
        if ret == 1 {
            return true;
        } else {
            return false;
        }
    }

    /// Decide wheter there is server-side support for the specified mechanism
    pub fn server_supports(&self, mech: &CStr) -> bool {
        // returns 1 if there is server support for the specific mechanism
        let ret = unsafe { gsasl_server_support_p(self.ctx, mech.as_ptr()) };
        if ret == 1 {
            return true;
        } else {
            return false;
        }
    }

    /// The callback is used by mechanisms to retrieve information, such as username and password,
    /// from the application. In a server, the callback is used to decide whether a user is
    /// permitted to log in or not. 
    /// With this function you install the callback for the given context.
    pub fn install_callback(&mut self, callback: Gsasl_callback_function) {
        unsafe { gsasl_callback_set(self.ctx, callback); }
    }

    pub fn client_start(&mut self, mech: &CStr) -> error::Result<Session> {
        let mut ptr: *mut Gsasl_session = ptr::null_mut();
        let res = unsafe {
            gsasl_client_start(self.ctx, mech.as_ptr(), &mut ptr as *mut *mut Gsasl_session)
        };

        if res != (GSASL_OK as libc::c_int) {
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

        if res != (GSASL_OK as libc::c_int) {
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
