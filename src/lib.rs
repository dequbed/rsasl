use gsasl_sys::*;
use gsasl_sys::Gsasl_rc::*;
use std::ptr;
use std::cell::RefCell;
use std::ffi::CStr;
use std::sync::{Mutex, MutexGuard};
use std::ops::{Drop, Deref, DerefMut};

mod buffer;
mod session;
pub mod error;
//mod callback;

pub use session::Session;
use buffer::SaslString;

pub use gsasl_sys::{
    self as sys,
    Gsasl_rc as ReturnCode,
    Gsasl_property as Property,
};

pub use session::Step;

pub use error::{
    SaslError,
    gsasl_err_to_str,
    gsasl_errname_to_str,
};

/// Main rsasl struct
///
/// This struct wraps a gsasl context ensuring `gsasl_init` and `gsasl_done` are called.
/// It implements `Deref` and `DerefMut` to the — unmanaged — `SaslCtx` that wraps the unsafe FFI
/// methods from GSASL with safe(r) Rust functions.
///
/// The reason for this split lays in callbacks - they are given pointers to the (C struct) context
/// and session they were called from which we wrap so the safe(r) Rust methods can be used
/// instead, but we MUST NOT call `done` on the context or the session afterwards.
pub struct SASL<D> {
    ctx: SaslCtx<D>
}
impl<D> SASL<D> {
    pub fn new() -> error::Result<Self> {
        let mut ctx = SaslCtx::from_ptr(ptr::null_mut());

        ctx.init()?;

        Ok(SASL { ctx })
    }
}
impl<D> Drop for SASL<D> {
    fn drop(&mut self) {
        // Clean up the Context so we do not leak memory
        // This is unsafe because using a Context after calling `done` is undefined behaviour — and
        // very likely to lead to a segmentation fault.
        unsafe { self.ctx.done() };
    }
}
impl<D> Deref for SASL<D> {
    type Target = SaslCtx<D>;
    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}
impl<D> DerefMut for SASL<D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ctx
    }
}

/// An unmanaged GSASL context
pub struct SaslCtx<D> {
    // The underlying context as returned by gsasl
    ctx: *mut Gsasl,

    // The data is actually stored in the application context, not in this struct. This phantom
    // marker allows us to use generics and ensures that the context is !Send if the stored data is
    // !Send
    phantom: std::marker::PhantomData<RefCell<D>>,
}

impl<D> SaslCtx<D> {
    /// Creates a new SASL context.
    ///
    /// This function should never be called by an external party directly. Please use the
    /// `SASL` struct that correctly initializes and deinitalizes the underlying context for you.
    pub(crate) fn from_ptr(ctx: *mut Gsasl) -> Self {
        let phantom = std::marker::PhantomData;
        Self { ctx, phantom }
    }

    /// Initialize a SASL context. Has to be run before most other functions are called
    fn init(&mut self) -> error::Result<()> {
        // Initialize the context
        let res = unsafe {
            gsasl_init(&mut (self.ctx) as *mut *mut Gsasl)
        };

        if res != (GSASL_OK as libc::c_int) {
            return Err(error::SaslError(res));
        }

        Ok(())
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
    pub(crate) fn install_callback_raw(&mut self, callback: Gsasl_callback_function) {
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

    /// Store some data in the SASL context
    ///
    /// This allows a callback to later access that data using `retrieve` or `retrieve_mut`
    pub fn store(&mut self, data: Box<D>) {
        // This is safe because the worst that can happen is that we leak a previously stored
        // value.
        unsafe {
            gsasl_callback_hook_set(self.ctx, Box::into_raw(data) as *mut libc::c_void)
        }
    }

    /// Retrieve the data stored with `store`, leaving nothing in its place
    ///
    /// This function will return `None` if no data was stored. This function is unsafe because we
    /// can not guarantee that there is currently nothing else that has a reference to the data
    /// which will turn into a dangling pointer if the returned Box is dropped
    pub unsafe fn retrieve(&mut self) -> Option<Box<D>> {
        // This function is unsa
        // Get a pointer to the current value
        let ptr = gsasl_callback_hook_get(self.ctx);
        // Set it to null because we now have sole ownership
        gsasl_callback_hook_set(self.ctx, std::ptr::null_mut());

        if !ptr.is_null() {
            Some(Box::from_raw(ptr as *mut D))
        } else {
            None
        }
    }

    /// Retrieve a mutable reference to the data stored with `store`
    ///
    /// This is an alternative to `retrieve_raw` that does not take ownership of the stored data,
    /// thus also not dropping it after it has left the current scope. Mainly useful for callbacks
    ///
    /// The function tries to return `None` if no data was stored.
    pub fn retrieve_mut(&mut self) -> Option<&mut D> {
        // This is safe because once you have given ownership of data to the context you can only
        // get it back using `unsafe` functions.
        unsafe {
            let ptr = gsasl_callback_hook_get(self.ctx) as *mut D;
            ptr.as_mut()
        }
    }

    /// Finalize the context.
    ///
    /// This is not exposed to consumers of the crate because it's use it very unsafe — you have to
    /// make sure that the caller is the only remaining user of the GSASL context and that the
    /// context is not used afterwards.
    pub(crate) unsafe fn done(&mut self) {
        gsasl_done(self.ctx);
    }
}
