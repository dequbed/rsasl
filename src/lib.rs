//! RSASL — Rustic bindings to GNU libgsasl
//!
//! [libgsasl](https://www.gnu.org/software/gsasl/) is a pure C, LGPL-2.1 (or later) licensed SASL
//! library. This crate provides a set of rusty abstractions on top of that library making it hard
//! to mis-use.
//!
//! The main struct in this library is the [`SASL`] struct. It handles resource allocation and
//! free-ing for you.
//!
//! For all but the most basic of applications you will want to also construct an
//! application-specific [`Callback`], which rsasl will use to ask for additional data required to
//! perform the handshake.

use gsasl_sys::*;
pub use gsasl_sys::Gsasl_rc::*;
use std::ptr;
use std::ffi::CString;
use std::ops::{Drop, Deref, DerefMut};

pub mod buffer;
pub mod session;
pub mod error;
mod callback;
mod mechanisms;

pub use callback::Callback;
pub use session::{SessionHandle, Session};
pub use buffer::SaslString;
pub use mechanisms::Mechanisms;

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

#[derive(Debug)]
/// Main rsasl struct
///
/// This struct wraps a gsasl context ensuring `gsasl_init` and `gsasl_done` are called.  It
/// implements `Deref` and `DerefMut` to the — unmanaged — [SaslCtx](struct.SaslCtx.html) that
/// wraps the unsafe FFI methods from GSASL with safe(r) Rust functions.
///
/// The reason for this split lays in callbacks - they are given pointers to the (C struct) context
/// and session they were called from which we wrap so the safe(r) Rust methods can be used
/// instead, but we MUST NOT call `done` on the context or the session afterwards.
///
/// The two type parameters restrict the types you can store / retrieve in callbacks; gsasl allows
/// to store two objects in the context and session so that the callback function can access them
/// despite being called with no reference to Rust's execution environment otherwise. They are
/// exposed in rsasl as [store](struct.SASL.html#method.store) and [retrieve](struct.SASL.html#method.retrieve_mut)
pub struct SASL<D,E> {
    ctx: SaslCtx<D,E>
}
impl<D,E> SASL<D,E> {
    pub fn new() -> error::Result<Self> {
        let mut ctx = SaslCtx::from_ptr(ptr::null_mut());

        ctx.init()?;

        Ok(SASL { ctx })
    }
}
impl<D,E> Drop for SASL<D,E> {
    fn drop(&mut self) {
        // Clean up the Context so we do not leak memory
        // This is unsafe because using a Context after calling `done` is undefined behaviour — and
        // very likely to lead to a segmentation fault.
        unsafe { self.ctx.done() };
    }
}
impl<D,E> Deref for SASL<D,E> {
    type Target = SaslCtx<D,E>;
    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}
impl<D,E> DerefMut for SASL<D,E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ctx
    }
}

#[derive(Debug)]
/// An unmanaged GSASL context
///
/// You rarely construct this directly. If you want a context as consumer of this crate construct a
/// [SASL struct](struct.SASL.html) instead which will ensure that the context is properly closed.
///
/// You will however be passed this struct in [Callbacks](trait.Callback.html) if you install one.
pub struct SaslCtx<D,E> {
    // The underlying context as returned by gsasl
    ctx: *mut Gsasl,

    // The data is actually stored in the application context, not in this struct. This phantom
    // marker allows us to use generics and ensures that the context is !Send if the stored data is
    // !Send
    appdata: std::marker::PhantomData<D>,
    sessdata: std::marker::PhantomData<E>,
}

impl<D, E> SaslCtx<D,E> {
    /// Creates a new SASL context.
    ///
    /// This function should never be called by an external party directly. Please use the
    /// `SASL` struct that correctly initializes and deinitalizes the underlying context for you.
    pub(crate) fn from_ptr(ctx: *mut Gsasl) -> Self {
        let appdata = std::marker::PhantomData;
        let sessdata = std::marker::PhantomData;
        Self { ctx, appdata, sessdata }
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
    pub fn client_mech_list(&self) -> error::Result<Mechanisms> {
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
            Ok(Mechanisms::from_sasl(s))
        }
    }

    /// return the list of supported mechanism on the server side as a space-separated string
    // The underlying pointer must be freed by the caller, so for the sake of easier ownership
    // this must return a SaslString and not a &str, &CStr or similar.
    pub fn server_mech_list(&self) -> error::Result<Mechanisms> {
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
            Ok(Mechanisms::from_sasl(s))
        }
    }

    /// Return wheter there is client-side support for the specified mechanism
    pub fn client_supports(&self, mech: &str) -> bool {
        // returns 1 if there is client support for the specific mechanism
        let ret = unsafe { gsasl_client_support_p(self.ctx, mech.as_ptr() as *const i8) };
        if ret == 1 {
            return true;
        } else {
            return false;
        }
    }

    /// Return wheter there is server-side support for the specified mechanism
    pub fn server_supports(&self, mech: &str) -> bool {
        // returns 1 if there is server support for the specific mechanism
        let ret = unsafe { gsasl_server_support_p(self.ctx, mech.as_ptr() as *const i8) };
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
    ///
    /// See the [trait documentation](trait.Callback.html) for details on how to use this function
    pub fn install_callback<C: Callback<D,E>>(&mut self) {
        self.install_callback_raw(Some(callback::wrap::<C, D, E>));
    }

    fn install_callback_raw(&mut self, callback: Gsasl_callback_function) {
        unsafe { gsasl_callback_set(self.ctx, callback); }
    }

    /// Start the client side of an authentication exchange
    ///
    /// Depending on the mechanism you have chosen this may need additional data from you (such as
    /// an authcid, and/or authzid and password for PLAIN). To provide that data either call
    /// `set_property` on the returned session or install a Callback.
    ///
    /// See [the gsasl documentation](https://www.gnu.org/software/gsasl/manual/gsasl.html#Using-a-callback) for
    /// how gsasl uses properties and callbacks.
    pub fn client_start(&mut self, mech: &str) -> error::Result<SessionHandle<E>> {
        let mut ptr: *mut Gsasl_session = ptr::null_mut();
        let mech_string = CString::new(mech).map_err(|_| { SaslError(GSASL_UNKNOWN_MECHANISM as libc::c_int) })?;
        let res = unsafe {
            gsasl_client_start(
                self.ctx, 
                mech_string.as_ptr(),
                &mut ptr as *mut *mut Gsasl_session)
        };

        if res != (GSASL_OK as libc::c_int) {
            Err(error::SaslError(res))
        } else {
            let session = SessionHandle::from_ptr(ptr);
            Ok(session)
        }
    }

    /// Start the server side of an authentication exchange
    ///
    /// Depending on the mechanism you have chosen this may need additional data from you (such as
    /// the ability to check authcid/authzid/password combinations for PLAIN). Either provide that
    /// data using calls to `set_property` on the returned session or install a Callback.
    ///
    /// See [the gsasl documentation](https://www.gnu.org/software/gsasl/manual/gsasl.html#Using-a-callback) for
    /// how gsasl uses properties and callbacks.
    pub fn server_start(&mut self, mech: &str) -> error::Result<SessionHandle<E>> {
        let mut ptr: *mut Gsasl_session = ptr::null_mut();
        let res = unsafe {
            gsasl_server_start(self.ctx, mech.as_ptr() as *const i8, &mut ptr as *mut *mut Gsasl_session)
        };

        if res != (GSASL_OK as libc::c_int) {
            Err(error::SaslError(res))
        } else {
            let session = SessionHandle::from_ptr(ptr);
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

    /// Run the configured callback
    pub fn callback(&mut self, session: &mut Session<E>, prop: Property) -> libc::c_int {
        unsafe { gsasl_callback(self.ctx, session.as_ptr(), prop) }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_test() {
        struct CB;
        impl Callback<u32, u64> for CB {
            fn callback(mut sasl: SaslCtx<u32, u64>, mut session: Session<u64>, _prop: Property) 
                -> libc::c_int
            {
                assert_eq!(sasl.retrieve_mut(), Some(&mut 0x55555555));
                assert_eq!(session.retrieve_mut(), Some(&mut 0xAAAAAAAAAAAAAAAA));
                GSASL_OK as libc::c_int
            }
        }

        let mut sasl = SASL::new().unwrap();
        sasl.install_callback::<CB>();
        sasl.store(Box::new(0x55555555));
        let mut session = sasl.client_start("PLAIN").unwrap();
        session.store(Box::new(0xAAAAAAAAAAAAAAAA));

        assert_eq!(GSASL_OK as libc::c_int,
            sasl.callback(&mut session, Property::GSASL_VALIDATE_SIMPLE));
    }

    #[test]
    fn callback_unset_test() {
        struct CB;
        impl Callback<u32, u64> for CB {
            fn callback(mut sasl: SaslCtx<u32, u64>, mut session: Session<u64>, _prop: Property) 
                -> libc::c_int
            {
                assert_eq!(sasl.retrieve_mut(), None);
                assert_eq!(session.retrieve_mut(), None);
                GSASL_OK as libc::c_int
            }
        }

        let mut sasl = SASL::new().unwrap();
        sasl.install_callback::<CB>();
        let mut session = sasl.client_start("PLAIN").unwrap();

        assert_eq!(GSASL_OK as libc::c_int,
            sasl.callback(&mut session, Property::GSASL_VALIDATE_SIMPLE));
    }
}
