// The Gsasl_propery enum has to be non-exhaustive. On the C-side it's defined as a number of
// constants, all of which are represented as values by bindgen (as long as the version of gsasl
// your system has is ABI-compatible with the one you built your software with).
#![allow(improper_ctypes_definitions)]

use crate::gsasl::consts::{GSASL_OK, Gsasl_property};
use crate::gsasl::gsasl::{Gsasl, Gsasl_session};
use crate::{SASL, Property};
use crate::session::Session;

/// Typesafe Callbacks via trait implementations
///
/// GSASL makes use of callbacks to retrieve data from an application and to allow it to make
/// decisions regarding the authentication process and outcome.
///
/// Whenever gsasl requires further information not already provided by
/// [`Session::set_property`](Session::set_property) it calls the configured callback function with
/// a `prop` value indicating what action to perform or what property to set.
/// 
/// #### An example for the server-side of a PLAIN authentication 
///
/// To authorize a PLAIN exchange the application callback will be called with the property
/// `Property::GSASL_VALIDATE_SIMPLE`. The callback can then access the properties `GSASL_AUTHID`,
/// `GSASL_AUTHZID` and `GSASL_PASSWORD` to check the provided credentials.
///
/// ```
/// use std::ffi::CString;
/// use rsasl_c2rust::consts::{GSASL_AUTHENTICATION_ERROR, GSASL_AUTHID, GSASL_NO_AUTHID, GSASL_NO_CALLBACK, GSASL_NO_PASSWORD, GSASL_PASSWORD, GSASL_VALIDATE_SIMPLE};
/// use rsasl::{SASL, Session, Callback, Property};
///
/// // Callback is an unit struct since no data can be accessed from it.
/// struct OurCallback;
///
/// impl Callback<(), ()> for OurCallback {
///     // Note that this function does not take `self`. The callback function has no access to
///     // data stored in the type the trait is implemented on.
///     fn callback(sasl: &mut SASL<(), ()>, session: &mut Session<()>, prop: Property) 
///         -> Result<(), u32>
///     {
///         // For brevity sake we use hard-coded credentials here.
///         match prop {
///             GSASL_VALIDATE_SIMPLE => {
///                 let authcid = session.get_property(GSASL_AUTHID)
///                     .ok_or(GSASL_NO_AUTHID)?;
///
///                 let password = session.get_property(GSASL_PASSWORD)
///                     .ok_or(GSASL_NO_PASSWORD)?;
///
///                 if authcid == CString::new("username").unwrap().as_ref()
///                     && password == CString::new("secret").unwrap().as_ref()
///                 {
///                     Ok(())
///                 } else {
///                     Err(GSASL_AUTHENTICATION_ERROR)
///                 }
///             }
///             _ => Err(GSASL_NO_CALLBACK)
///         }
///     }
/// }
/// ```
/// 
/// #### Accessing application data in callbacks
///
/// Due to callbacks having to pass through FFI data can not be safely accessed via `self`
/// parameters. Instead an application needs to store values that the callbacks need in the
/// global `SASL` context or the `Session` context.
///
/// To this end an application can use either [`SASL::store`](SASL::store) for global data
/// available to all Session that is retrieved using [`SASL::retrieve_mut`](SASL::retrieve_mut) or
/// the equivalent [`Session::store`](Session::store) and
/// [`Session::retrieve_mut`](Session::retrieve_mut) for data only available to one specific
/// authentication exchange.
///
/// ##### Typesafety
///
/// Typesafety is ensured by using generic type parameters. Thanks to type inference is it usually
/// not necessary to spell out the types for the `SASL` and `Session` structs:
///
/// ```
/// use rsasl::{SASL, Session, Callback, Property};
/// struct TypedCallback;
///
/// impl Callback<u64, String> for TypedCallback {
///     fn callback(sasl: &mut SASL<u64, String>, session: &mut Session<String>, _prop: Property)
///         -> Result<(), u32>
///     {
///         // retrieve the stored global data
///         let global_data: &mut u64 = sasl.retrieve_mut().unwrap();
///
///         // We don't always set session data, so we can't unwrap here.
///         let session_data: Option<&mut String> = session.retrieve_mut();
///
///         match global_data {
///             // Session data is only valid for that specific session;
///             1 => assert_eq!(session_data, Some(&mut "Hello SASL".to_string())),
///
///             // the second time around no data was stored. This results in retrieve_mut()
///             // returning `None`:
///             2 => assert_eq!(session_data, None),
///
///             3 => assert_eq!(session_data, Some(&mut "Hello again".to_string())),
///
///
///             _ => assert!(false, "Unexpected value of `global_data`"),
///         }
///
///         // You can modify global data in callbacks since you have transfered ownership of it to
///         // the `SASL` context which ensure exclusive access. If you need shared access use `Arc`,
///         // `Mutex`, etc.
///         *global_data += 1;
///
///         Ok(())
///     }
/// }
///
/// fn main() {
///     use rsasl_c2rust::consts::{GSASL_OK, GSASL_SERVICE};
/// let mut sasl = SASL::new().unwrap();
///     sasl.install_callback::<TypedCallback>();
///
///     {
///         // Start an example exchange
///         let mut session = sasl.client_start("PLAIN").unwrap();
///
///         // This is global data so scope is irrelevant
///         sasl.store(Box::new(1));
///
///         // This data however is only valid for this one session
///         session.store(Box::new("Hello SASL".to_string()));
///
///         let rt = sasl.callback(&mut session, GSASL_SERVICE);
///         assert_eq!(rt, GSASL_OK as libc::c_int)
///     }
///
///     {
///         // Start a new session...
///         let mut session = sasl.client_start("PLAIN").unwrap();
///         // ...but don't store any session-specific data
///
///         let rt = sasl.callback(&mut session, GSASL_SERVICE);
///         assert_eq!(rt, GSASL_OK as libc::c_int)
///     }
///
///     {
///         // Start a new session...
///         let mut session = sasl.client_start("PLAIN").unwrap();
///         // ...and store different data than the first time
///         session.store(Box::new("Hello again".to_string()));
///
///         let rt = sasl.callback(&mut session, GSASL_SERVICE);
///         assert_eq!(rt, GSASL_OK as libc::c_int)
///     }
///
/// }
/// ```


pub trait Callback<D,E> {
    /// Application callback function to be implemented
    ///
    /// The parameters passed are the global SASL context, the session context and the `Property`
    /// indicating what data has to be provided or what action has to be taken.
    ///
    /// The callback should return `Ok(())` on success and and `Err(ReturnCode)` on failure with
    /// the ReturnCode indicating the kind of error.
    ///
    /// See the [gsasl website](https://www.gnu.org/software/gsasl/manual/gsasl.html#Error-values)
    /// for a list of possible return value with their descriptions.
    fn callback(sasl: &mut SASL<D,E>, session: &mut Session<E>, prop: Property) -> Result<(),
        u32>;
}

pub(crate) fn wrap<C: Callback<D,E>, D, E>(
    ctx: *mut Gsasl,
    sctx: *mut Gsasl_session,
    prop: Gsasl_property)
    -> libc::c_int
{
    let mut sasl = SASL::from_ptr(unsafe { &mut *ctx as &'static mut Gsasl });
    let mut session = Session::from_ptr(sctx);
    C::callback(&mut sasl, &mut session, prop as Property)
        .err()                              // Extract the error return code if it exists
        .unwrap_or(GSASL_OK)    // Otherwise set the return value to GSASL_OK
        as i32
}
