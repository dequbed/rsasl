//! rSASL — Rustic bindings to GNU libgsasl
//!
//! [libgsasl](https://www.gnu.org/software/gsasl/) is a pure C, LGPL-2.1 (or later) licensed SASL
//! library. This crate provides safe bindings to that library, providing access to a large number
//! of authentication mechanisms:
//! - EXTERNAL
//! - ANONYMOUS
//! - PLAIN
//! - LOGIN
//! - CRAM-MD5
//! - DIGEST-MD5
//! - SCRAM-SHA-1
//! - NTLM
//! - SECURID
//! - GSSAPI
//! - GS2-KRB5
//! - SAML20
//! - OPENID20
//! - KERBEROS_V5
//!
//! #### Usage
//!
//! To use this library a [`SASL`](SASL) struct has to be constructed first. Using this struct the
//! list of supported mechanisms for authentication can be accessed via
//! [`SASL::client_mech_list`](SASL::client_mech_list) and
//! [`SASL::server_mech_list`](SASL::server_mech_list).
//!
//! For each authentication exchange a [`Session`](Session) need to be created using
//! [`SASL::client_start`](SASL::client_start) or [`SASL::server_start`](SASL::server_start),
//! depending on if the application is acting as the client or server role respectively.
//!
//! The returned `Session` can be preloaded with required data for authentication, see
//! [`Session::set_property`].
//!
//! #### Properties
//!
//! gsasl uses what it calls 'Properties' to send authentication data to and from an application.
//! These properties can either be "logic properties" indicating that the application need to make
//! a decision and "data properties" storing a value such as an username or password.
//! A detailed explanation of the available properties and their use in mechanism can be found at
//! the [gsasl website](https://www.gnu.org/software/gsasl/manual/gsasl.html#Properties).
//!
//! #### Callbacks
//!
//! rSASL uses callbacks to retrieve properties from an application and to allow the
//! application to make decisions.
//!
//! An explanation on how to implement decision logic and callbacks in Rust can be [found
//! in the Callback documentation](Callback).
//!
//! While Server applications will usually need to implement callbacks Client applications can
//! forgo this and preemptively set properties via
//! [`Session::set_property`](Session::set_property):
//!
//! ```
//! use rsasl::{SASL, Property, Step::{Done, NeedsMore}};
//! use rsasl_c2rust::consts::{GSASL_AUTHID, GSASL_PASSWORD};
//! pub fn main() {
//!     // Create an untyped SASL because we won't store/retrieve information in the context since
//!     // we don't use callbacks.
//! let mut sasl = SASL::new_untyped().unwrap();
//!
//!     // Usually you would first agree on a mechanism with the server, for demostration purposes
//!     // we directly start a PLAIN "exchange"
//!     let mut session = sasl.client_start("PLAIN").unwrap();
//!
//!
//!     // Set the username that will be used in the PLAIN authentication
//!     session.set_property(GSASL_AUTHID, "username".as_bytes());
//!
//!     // Now set the password that will be used in the PLAIN authentication
//!     session.set_property(GSASL_PASSWORD, "secret".as_bytes());
//!
//!
//!     // Do an authentication step. In a PLAIN exchange there is only one step, with no data.
//!     let step_result = session.step(&[]).unwrap();
//!
//!     match step_result {
//!         Done(buffer) => assert_eq!(buffer.as_ref(), "\0username\0secret".as_bytes()),
//!         NeedsMore(_) => assert!(false, "PLAIN exchange took more than one step"),
//!     }
//! }
//! ```

use std::ptr;
use std::ffi::{CString, CStr};


// Re-Export DiscardOnDrop so people can write rsasl::DiscardOnDrop<SASL<D,E>> without having to
// import the discard crate.
pub use discard::{Discard, DiscardOnDrop};

use gsasl::callback::{gsasl_callback, gsasl_callback_hook_get, gsasl_callback_hook_set,
                gsasl_callback_set};

pub mod buffer;
pub mod session;
pub mod error;
mod callback;
mod mechanisms;

mod gsasl;

pub use callback::Callback;
pub use session::Session;
pub use buffer::SaslString;
pub use mechanisms::Mechanisms;

pub use session::Step;

use crate::gsasl::consts::{GSASL_MECHANISM_PARSE_ERROR, GSASL_OK, GSASL_UNKNOWN_MECHANISM};
use crate::gsasl::done::gsasl_done;
use crate::gsasl::gsasl::{Gsasl, Gsasl_callback_function, Gsasl_session};
use crate::gsasl::init::gsasl_init;
use crate::gsasl::listmech::{gsasl_client_mechlist, gsasl_server_mechlist};
use crate::gsasl::suggest::gsasl_client_suggest_mechanism;
use crate::gsasl::supportp::{gsasl_client_support_p, gsasl_server_support_p};
use crate::gsasl::xstart::{gsasl_client_start, gsasl_server_start};
pub use crate::gsasl::consts::Gsasl_property as Property;

pub use error::{
    SaslError,
    rsasl_err_to_str,
    gsasl_err_to_str,
    rsasl_errname_to_str,
    gsasl_errname_to_str,
};

#[derive(Debug)]
/// Global SASL Context wrapper implementing housekeeping functionality
///
/// This struct contains the global gsasl context allowing you to start authentication exchanges.
///
/// It implements housekeeping functionality, calling `gsasl_init` and `gsasl_done` as required.
///
/// The type parameters `D` and `E` define the types you can store / retrieve in callbacks; gsasl
/// allows to store one object in both the context and session allowing callbacks to access values
/// from the application despite going through a FFI layer.
///
/// Values stored in the global context using [store](SASL::store) are available to all callbacks
/// via [retrieve_mut](SASL::retrieve_mut). Values stored with [`Session::store`](Session::store)
/// are only available in that session via [`Session::retrieve_mut`](Session::retrieve_mut).
///
/// The stored value can be extracted again using [`retrieve`](SASL::retrieve) and it's 
/// [`Session` requivalent](Session::retrieve).
pub struct SASL<D,E> {
    // The underlying context as returned by gsasl
    ctx: *mut Gsasl,

    // The data is actually stored in the application context, not in this struct. This phantom
    // marker allows us to use generics and ensures that the context is !Send if the stored data is
    // !Send
    appdata: std::marker::PhantomData<D>,
    sessdata: std::marker::PhantomData<E>,
}

/// Utility type definition to make the outer SASL type spellable without manually importing the
/// discard crate.
pub type RSASL<D,E> = DiscardOnDrop<SASL<D,E>>;

impl<D, E> SASL<D,E> {
    /// Create a fresh GSASL context from scratch.
    ///
    /// The context retrieved from this is wrapped in a [`DiscardOnDrop`](discard::DiscardOnDrop).
    /// The purpose of this wrapping is to ensure that finalizer functions are called when the
    /// context is dropped.
    /// `DiscardOnDrop` implements both [`Deref`](std::ops::Deref) and
    /// [`DerefMut`](std::ops::DerefMut), making the wrapping transparent to you.
    /// If you want to intentionally remove the Context from the wrapping you can call
    /// [`DiscardOnDrop::leak`](discard::DiscardOnDrop::leak), allowing you to manually handle
    /// finalizing the context.
    pub fn new() -> error::Result<DiscardOnDrop<Self>> {
        let mut ctx = Self::from_ptr(ptr::null_mut());

        ctx.init()?;

        Ok(DiscardOnDrop::new(ctx))
    }

    /// Creates a new SASL context.
    ///
    /// This function should never be called by an external party directly. Use the `new`
    /// constructor that correctly initializes the context.
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
            return Err(error::SaslError(res as u32));
        }

        Ok(())
    }

    /// Returns the list of Client Mechanisms supported by this library.
    ///
    /// Important note: This will make no attempt to check if the application has provided the
    /// required data for the listed mechanisms. For example this will return the `GSSAPI` and
    /// `KERBEROS_V5` mechanism if the system gsasl was linked with a libkrb5, independent of if
    /// the application has a valid ticket.
    pub fn client_mech_list(&self) -> error::Result<Mechanisms> {
        // rustc's borrow checker can't prove that we will never read this before having
        // initialized it so this *must* be initialized by us.
        let mut out = ptr::null_mut();

        // Call into libgsasl. As per usual ffi is unsafe
        let ret = unsafe { gsasl_client_mechlist(self.ctx, &mut out as *mut *mut libc::c_char) };

        // Take ownership of the output buffer so that it will always be freed and we don't leak
        // memory.
        let s = SaslString::from_raw(out);

        if ret != (GSASL_OK as libc::c_int) {
            // In the error case `s` will simply be dropped and freed.

            Err(error::SaslError(ret as u32))
        } else {
            // If libgsasl does not return an error we can assume that out has been filled with
            // valid data.
            Ok(Mechanisms::from_sasl(s))
        }
    }

    /// Returns the list of Server Mechanisms supported by this library.
    ///
    /// Important note: This will make no attempt to check if the application has provided the
    /// required data for the listed mechanisms. For example this will return the `GSSAPI` and
    /// `KERBEROS_V5` mechanism if the system gsasl was linked with a libkrb5, independent of if
    /// the application has a valid keytab.
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

            Err(error::SaslError(ret as u32))
        } else {
            // If libgsasl does not return an error we can assume that out has been filled with
            // valid string data.
            Ok(Mechanisms::from_sasl(s))
        }
    }

    /// Suggests a mechanism to use from a given list of Mechanisms. Returns
    /// Err(GSASL_UNKNOWN_MECHANISM) if there was no supported mechanism found in the given list,
    /// and Err(GSASL_MECHANISM_PARSE_ERROR) if the returned mechanism name is invalid.
    // The ptr returned by the ffi call is typed as 'const char*', so it should be valid for as
    // long as libgsasl is loaded.
    pub fn suggest_client_mechanism(&self, mechs: Mechanisms) -> Result<&str, SaslError> {
        unsafe {
            let ptr = gsasl_client_suggest_mechanism(self.ctx, mechs.as_raw_ptr());
            if ptr.is_null() {
                Err(SaslError(GSASL_UNKNOWN_MECHANISM))
            } else {
                let cstr = CStr::from_ptr(ptr);
                cstr.to_str()
                    .map_err(|_: std::str::Utf8Error|
                        SaslError(GSASL_MECHANISM_PARSE_ERROR))
            }
        }
    }

    /// Returns wheter there is client-side support for the specified mechanism
    pub fn client_supports(&self, mech: &CStr) -> bool {
        // returns 1 if there is client support for the specific mechanism
        let ret = unsafe { gsasl_client_support_p(self.ctx, mech.to_bytes_with_nul().as_ptr() as *const libc::c_char) };
        if ret == 1 {
            return true;
        } else {
            return false;
        }
    }

    /// Returns wheter there is server-side support for the specified mechanism
    pub fn server_supports(&self, mech: &CStr) -> bool {
        // returns 1 if there is server support for the specific mechanism
        let ret = unsafe { gsasl_server_support_p(self.ctx, mech.as_ptr() as *const libc::c_char) };
        if ret == 1 {
            return true;
        } else {
            return false;
        }
    }

    /// Install a callback.
    ///
    /// Callbacks are used to retrieve information, such as username and password, from the
    /// application. In a server, the callback is additionally used make decisions such as whether
    /// a user is permitted to log in or not. 
    ///
    /// See the [callback documentation](Callback) for details on how to use this function
    ///
    /// Do note that the generic types `D` and `E` need to match between `SASL`, `Session` and
    /// `Callback` to ensure typesafety. [More information](Callback#typesafety)
    pub fn install_callback<C: Callback<D,E>>(&mut self) {
        self.install_callback_raw(Some(callback::wrap::<C, D, E>));
    }

    fn install_callback_raw(&mut self, callback: Gsasl_callback_function) {
        unsafe { gsasl_callback_set(self.ctx, callback); }
    }

    /// Starts a authentication exchange as the client role
    ///
    /// Depending on the mechanism chosen this may need additional data from the application, such
    /// as an authcid, optional authzid and password for PLAIN. To provide that data an application
    /// has to either call `set_property` before running the step that requires the data, or
    /// install a callback.
    ///
    /// See [the gsasl
    /// documentation](https://www.gnu.org/software/gsasl/manual/gsasl.html#Properties) for what
    /// mechanism uses what properties.
    pub fn client_start(&mut self, mech: &str) -> error::Result<DiscardOnDrop<Session<E>>> {
        let mut ptr: *mut Gsasl_session = ptr::null_mut();

        // Convert the mechanism &str to a zero-terminated String.
        let cmech = CString::new(mech)
            .map_err(|_| SaslError(GSASL_MECHANISM_PARSE_ERROR))?;

        let res = unsafe {
            gsasl_client_start(
                self.ctx, 
                cmech.as_ptr(),
                &mut ptr as *mut *mut Gsasl_session)
        };

        if res != (GSASL_OK as libc::c_int) {
            Err(error::SaslError(res as u32))
        } else {
            let session = Session::from_ptr(ptr);
            Ok(DiscardOnDrop::new(session))
        }
    }

    /// Starts a authentication exchange as the server role
    ///
    /// An application acting as server will most likely need to implement a callback to check the
    /// authentication data provided by the user.
    ///
    /// See [Callback](Callback) on how to implement callbacks.
    ///
    /// See [the gsasl documentation](https://www.gnu.org/software/gsasl/manual/gsasl.html#Using-a-callback) for
    /// how gsasl uses properties and callbacks.
    pub fn server_start(&mut self, mech: &str) -> error::Result<DiscardOnDrop<Session<E>>> {
        let mut ptr: *mut Gsasl_session = ptr::null_mut();

        // Convert the mechanism &str to a zero-terminated String.
        let cmech = CString::new(mech)
            .map_err(|_| SaslError(GSASL_MECHANISM_PARSE_ERROR))?;

        let res = unsafe {
            gsasl_server_start(
                self.ctx,
                cmech.as_ptr(),
                &mut ptr as *mut *mut Gsasl_session
            )
        };

        if res != (GSASL_OK as libc::c_int) {
            Err(error::SaslError(res as u32))
        } else {
            let session = Session::from_ptr(ptr);
            Ok(DiscardOnDrop::new(session))
        }
    }

    /// Store some data in the SASL context
    ///
    /// This allows a callback to later access that data using [`retrieve`](Self::retrieve) or
    /// [`retrieve_mut`](Self::retrieve_mut)
    pub fn store(&mut self, data: Box<D>) {
        // This is safe because the worst that can happen is that we leak a previously stored
        // value.
        unsafe {
            gsasl_callback_hook_set(self.ctx, Box::into_raw(data) as *mut libc::c_void)
        }
    }

    /// Retrieve the data stored with [`store`](Self::store), leaving nothing in its place
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

    /// Retrieve a mutable reference to the data stored with [`store`](Self::store)
    ///
    /// This function does not take ownership of the stored data, thus also not dropping it after
    /// it has left the current scope.
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

    /// Run the configured callback.
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

impl SASL<(), ()> {
    /// Construct an untyped SASL
    ///
    /// This is mostly useful for client applications when no callback will be installed and no
    /// information stored or retrieved in either the global or session context.
    pub fn new_untyped() -> error::Result<DiscardOnDrop<Self>> {
        SASL::new()
    }
}


impl<D,E> Discard for SASL<D,E> {
    fn discard(mut self) {
        // This block is save as long as this is the only remaining copy of *this* gsasl context.
        // This should always hold since the only way to duplicate the context as an user of this
        // crate is by calling `callback` or having the Callback called in an ongoing exchange,
        // which should be prevented by the borrow checker.
        unsafe {
            // Retrieve and drop the stored value.
            self.retrieve();
            self.done();
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter::FromIterator;
    use crate::gsasl::consts::GSASL_VALIDATE_SIMPLE;

    #[test]
    fn callback_test() {
        struct CB;
        impl Callback<u32, u64> for CB {
            fn callback(sasl: &mut SASL<u32, u64>, session: &mut Session<u64>, _prop: Property) 
                -> Result<(), u32>
            {
                assert_eq!(sasl.retrieve_mut(), Some(&mut 0x55555555));
                assert_eq!(session.retrieve_mut(), Some(&mut 0xAAAAAAAAAAAAAAAA));
                Ok(())
            }
        }

        let mut sasl = SASL::new().unwrap();
        sasl.install_callback::<CB>();
        sasl.store(Box::new(0x55555555));
        let mut session = sasl.client_start("PLAIN").unwrap();
        session.store(Box::new(0xAAAAAAAAAAAAAAAA));

        assert_eq!(GSASL_OK as libc::c_int,
            sasl.callback(&mut session, GSASL_VALIDATE_SIMPLE));
    }

    #[test]
    fn callback_unset_test() {
        struct CB;
        impl Callback<u32, u64> for CB {
            fn callback(sasl: &mut SASL<u32, u64>, session: &mut Session<u64>, _prop: Property) 
                -> Result<(), u32>
            {
                assert_eq!(sasl.retrieve_mut(), None);
                assert_eq!(session.retrieve_mut(), None);
                Ok(())
            }
        }

        let mut sasl = SASL::new().unwrap();
        sasl.install_callback::<CB>();
        let mut session = sasl.client_start("PLAIN").unwrap();

        assert_eq!(GSASL_OK as libc::c_int,
            sasl.callback(&mut session, GSASL_VALIDATE_SIMPLE));
    }

    #[test]
    fn suggest_good() {
        let mechs = vec!["PLAIN", "INVALID", "SCRAM-SHA-256"];
        let mut sasl = SASL::new_untyped().unwrap();
        let suggest = sasl.suggest_client_mechanism(Mechanisms::from_iter(mechs.iter()));

        assert!(suggest.is_ok());
        assert_eq!("SCRAM-SHA-256", suggest.unwrap());
    }

    #[test]
    fn suggest_fail_on_invalid() {
        let mechs = vec!["INVALID", "ALSOINV", "MOREINV3"];
        let mut sasl = SASL::new_untyped().unwrap();
        let suggest = sasl.suggest_client_mechanism(Mechanisms::from_iter(mechs.iter()));

        assert_eq!(Err(SaslError(GSASL_UNKNOWN_MECHANISM)), suggest);
    }
}
