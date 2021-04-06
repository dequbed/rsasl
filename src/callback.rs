use crate::{SASL, Property};
use crate::session::Session;

/// Callback instance
///
/// GSASL makes heavy use of callbacks to retrieve data from your application.
/// Whenever gsasl requires further information it calls the callback with the `prop` indicating
/// what action the callback is required to perform. 
///
/// For example if you do a PLAIN authentication
/// as a client the callback may be called three times with `GSASL_AUTHID`, `GSASL_AUTHZID` and
/// `GSASL_PASSWORD` set respectively expecting you to call `session.set_property` for those
/// properties and provide the information.
///
/// If you are performing a PLAIN authentication as Server you will instead be called with
/// `GSASL_VALIDATE_SIMPLE`, expected to read the authcid/authzid/password using
/// `session.get_property` and return `GSASL_OK` or `GSASL_AUTHENTICATION_ERROR` (or any other
/// non-`GSASL_OK`) return code to indicate successful or failed authentication.
///
/// To install a callback implement this trait on an unit struct which you pass to
/// SASL::install_callback():
///
/// Due to rsasl wrapping a C library you can't safely access data using a `self` parameter. If you
/// need to transfer data into the callback you will have to use
/// [`SaslCtx::store`](method@crate::SaslCtx::store) or
/// [`Session::store`](method@crate::session::Session::store). Those two functions differ in that
/// data stored via the former can be accessed from all sessions including those created after the
/// call to `store` while data set by the latter can only be accessed from the session it was
/// stored in.
///
/// ```
/// use rsasl::{SASL, Callback, Session, Property};
/// struct CB;
/// impl Callback<(), ()> for CB {
///     // Note that this function does *not* take `self`. You can not access data from the type
///     // you are implementing this trait on
///     fn callback(sasl: SASL<(), ()>, session: Session<()>, prop: Property) -> libc::c_int {
///         // While you don't have access to data from your system directly you can call
///         // SaslCtx::retrieve_mut() here and access data you previously stored
///         rsasl::GSASL_OK as libc::c_int
///     }
/// }
/// let mut sasl = SASL::new().unwrap();
/// sasl.install_callback::<CB>();
/// ```
///
/// The type parameters here 
pub trait Callback<D,E> {
    fn callback(sasl: SASL<D,E>, session: Session<E>, prop: Property) -> libc::c_int;
}

pub(crate) extern "C" fn wrap<C: Callback<D,E>, D, E>(
    ctx: *mut gsasl_sys::Gsasl, 
    sctx: *mut gsasl_sys::Gsasl_session, 
    prop: gsasl_sys::Gsasl_property)
    -> libc::c_int
{
    let sasl = SASL::from_ptr(ctx);
    let session = Session::from_ptr(sctx);
    C::callback(sasl, session, prop as Property)
}
