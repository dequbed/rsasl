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

use std::ffi::CStr;
use std::fmt::Debug;

pub use libc;

// Re-Export DiscardOnDrop so people can write rsasl::DiscardOnDrop<SASL<D,E>> without having to
// import the discard crate.
pub use discard::{Discard, DiscardOnDrop};

pub mod buffer;
pub mod session;
pub mod error;
mod callback;

mod gsasl;
mod registry;

pub use gsasl::consts;

pub use callback::Callback;
pub use session::Session;
pub use buffer::SaslString;

pub use session::Step;

use crate::gsasl::consts::{GSASL_MECHANISM_PARSE_ERROR, GSASL_OK, GSASL_UNKNOWN_MECHANISM};
use crate::gsasl::gsasl::{CMechBuilder, MechContainer, Mech, Mechanism, MechanismBuilder, MechanismVTable};
pub use crate::gsasl::consts::Gsasl_property as Property;

pub use error::{
    SaslError,
    rsasl_err_to_str,
    rsasl_errname_to_str,
};
use crate::consts::RsaslError;
use crate::gsasl::init::register_builtin_mechs;
use crate::session::AuthSession;

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
pub struct SASL<'sasl> {
    mechs: Vec<Box<dyn Mech>>,
    callback: Option<&'sasl dyn Callback>,
}

impl SASL<'_> {
    pub fn register_cmech(&mut self, name: &'static str,
                          client: MechanismVTable,
                          server: MechanismVTable)
    {
        let mut mech = MechContainer {
            name,
            client: CMechBuilder { vtable: client },
            server: CMechBuilder { vtable: server }
        };
        mech.init();
        self.mechs.push(Box::new(mech));
    }

    pub fn register<C: 'static + MechanismBuilder, S: 'static + MechanismBuilder>(
        &mut self,
        name: &'static str,
        client: C,
        server: S)
    {
        let mut mech = Box::new(MechContainer { name, client, server });
        mech.init();
        self.mechs.push(mech);
    }

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
    pub fn new() -> Result<Self, RsaslError> {
        let mut this = Self {
            mechs: Vec::new(),
            callback: None,
        };

        unsafe {
            let rc = register_builtin_mechs(&mut this);
            if rc == GSASL_OK as libc::c_int {
                Ok(this)
            } else {
                Err(rc as libc::c_uint)
            }
        }
    }

    /// Returns the list of Client Mechanisms supported by this library.
    ///
    /// Important note: This will make no attempt to check if the application has provided the
    /// required data for the listed mechanisms. For example this will return the `GSSAPI` and
    /// `KERBEROS_V5` mechanism if the system gsasl was linked with a libkrb5, independent of if
    /// the application has a valid ticket.
    pub fn client_mech_list(&self) -> error::Result<&[&str]> {
        todo!()
    }

    /// Returns the list of Server Mechanisms supported by this library.
    ///
    /// Important note: This will make no attempt to check if the application has provided the
    /// required data for the listed mechanisms. For example this will return the `GSSAPI` and
    /// `KERBEROS_V5` mechanism if the system gsasl was linked with a libkrb5, independent of if
    /// the application has a valid keytab.
    pub fn server_mech_list(&self) -> error::Result<&[&str]> {
todo!()
    }

    /// Suggests a mechanism to use from a given list of Mechanisms. Returns
    /// Err(GSASL_UNKNOWN_MECHANISM) if there was no supported mechanism found in the given list,
    /// and Err(GSASL_MECHANISM_PARSE_ERROR) if the returned mechanism name is invalid.
    pub fn suggest_client_mechanism(&self, _mechs: &[&str]) -> Result<&str, SaslError> {
        todo!()
    }

    /// Returns wheter there is client-side support for the specified mechanism
    pub fn client_supports(&self, _mech: &CStr) -> bool {
todo!()
    }

    /// Returns wheter there is server-side support for the specified mechanism
    pub fn server_supports(&self, _mech: &CStr) -> bool {
todo!()
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
    pub fn client_start(&self, mech: &str) -> Result<AuthSession, SaslError> {
        for builder in self.mechs.iter() {
            if builder.name() == mech {
                let mechanism = builder.client().start(&self)?;
                return Ok(AuthSession::new(self.callback, mechanism));
            }
        }

        Err(SaslError::new(GSASL_UNKNOWN_MECHANISM))
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
    pub fn server_start(&self, mech: &str)
        -> Result<AuthSession, RsaslError>
    {
        for builder in self.mechs.iter() {
            if builder.name() == mech {
                let mechanism = builder.server().start(&self)?;
                return Ok(AuthSession::new(self.callback, mechanism));
            }
        }

        Err(GSASL_UNKNOWN_MECHANISM)
    }

    /// Run the configured callback.
    pub fn callback(&mut self, _session: &mut Session, _prop: Property) -> libc::c_int {
        todo!()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_rsasl() {
        let ctx = SASL::new().unwrap();
        println!("{:?}", ctx);
    }
}