use crate::{SaslCtx, Property};
use crate::session::Session;

/// Callback instance
///
/// To install a callback implement this trait on an unit struct which you pass to
/// SASL::install_callback():
///
/// ```
/// struct CB;
/// impl Callback<(), ()> for CB {
///     // Note that this function does *not* take `self`. You can not access data from the type
///     // you are implementing this trait on
///     fn callback(sasl: SaslCtx<()>, session: Session<()>, prop: Property) -> libc::c_int {
///         // While you don't have access to data from your system directly you can call
///         // SaslCtx::retrieve_mut() here and access data you previously stored
///         rsasl::GSASL_OK as libc::c_int
///     }
/// }
/// let sasl = SASL::new();
/// sasl.install_callback<CB>();
/// ```
pub trait Callback<D,E> {
    fn callback(sasl: SaslCtx<D>, session: Session<E>, prop: Property) -> libc::c_int;
}

pub(crate) extern "C" fn wrap<C: Callback<D,E>, D, E>(
    ctx: *mut gsasl_sys::Gsasl, 
    sctx: *mut gsasl_sys::Gsasl_session, 
    prop: gsasl_sys::Gsasl_property)
    -> libc::c_int
{
    let sasl = SaslCtx::from_ptr(ctx);
    let session = Session::from_ptr(sctx);
    C::callback(sasl, session, prop as Property)
}
