//! User-provided callbacks
//!
//! Make very generic data go from user to mechanism and vice versa through the protocol impl
//! that should not need to care about the shape of this data.
//! Yeah, *all* the runtime reflection.

use thiserror::Error;
use core::marker::PhantomData;

use crate::error::SessionError;
use crate::property::Property;

use crate::typed::{tags, Erased, Tagged};
use crate::validate::{Validate, ValidationError};

// Re-Exports
pub use crate::context::Context;
pub use crate::session::SessionData;

pub trait SessionCallback {
    /// Answer requests by mechanism implementation for some Properties
    ///
    /// These requests come in one of two flavours: 'Satisfiable' requests asking that a value for
    /// some [`Property`] is provided, and 'Actionable' requests that instead need a specific
    /// action to be taken, usually performing sideband authentication to a users SSO IdP.
    ///
    /// Since it's not possible for the compiler to know at compile time which mechanism will be
    /// in use callbacks makes use of runtime reflection. This reflection is implemented by
    /// the [`Request`] type.
    ///
    /// Callbacks are also passed a [`SessionData`] and a [`Context`], providing access to data from
    /// the current [`Session`](crate::session::Session) and from the mechanism implementation. The
    /// data that can be provided via the `Context` is different for each mechanism and side, and
    /// may also change depending on the step the authentication is in, refer to the documentation
    /// of each mechanism that is planned to be supported for details.
    ///
    /// The callback is used when doing either a server-side or a client-side authentication. An
    /// example for an implementation on the client-side could look like so:
    /// ```rust
    /// # use rsasl::callback::{Request, SessionCallback, Context, SessionData};
    /// # use rsasl::prelude::*;
    /// # use rsasl::property::{AuthId, Password, AuthzId, OpenID20AuthenticateInBrowser, Realm};
    /// # struct CB;
    /// # impl CB {
    /// # fn interactive_get_username(&self) -> &str { unimplemented!() }
    /// # }
    /// # fn open_browser_and_go_to(url: &str) { }
    /// # impl SessionCallback for CB {
    /// fn callback(&self, session: &SessionData, context: &Context, request: &mut Request<'_>)
    ///     -> Result<(), SessionError>
    /// {
    ///     // Some requests are to provide a value for the given property by calling `satisfy`.
    ///     request
    ///         // satisfy_with only runs the provided closure if the type is correct
    ///         .satisfy_with::<AuthId, _>(|| self.interactive_get_username())?
    ///         // satisfy calls can be chained, making use of short-circuiting
    ///         .satisfy::<Password>(b"password")?
    ///         .satisfy::<AuthzId>("authzid")?;
    ///
    ///     // Other requests are to do a given action:
    ///     if let Some(url) = request.get_action::<OpenID20AuthenticateInBrowser>() {
    ///         open_browser_and_go_to(url);
    ///         return Ok(());
    ///     }
    ///     // Additional parameters can be retrieved from the provided `Context`:
    ///     if let Some("MIT.EDU") = context.get_ref::<Realm>() {
    ///         // Special handling
    ///     }
    ///
    ///     // While there exists an error `NoCallback`, returning `Ok` here is correct too.
    ///     Ok(())
    /// }
    /// # }
    /// ```
    ///
    fn callback(
        &self,
        session_data: &SessionData,
        context: &Context,
        request: &mut Request,
    ) -> Result<(), SessionError> {
        // silence the 'arg X not used' errors without having to prefix the parameter names with _
        let _ = (session_data, context, request);
        Ok(())
    }

    /// Validate an authentication exchange
    ///
    /// This callback will mostly be issued on the server side of an authentication exchange to
    /// validate the data passed in by the client side like username/password for `PLAIN`.
    ///
    fn validate(
        &self,
        session_data: &SessionData,
        context: &Context,
        validate: &mut Validate<'_>,
    ) -> Result<(), ValidationError> {
        // silence the 'arg X not used' errors without having to prefix the parameter names with _
        let _ = (session_data, context, validate);
        Ok(())
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct TOKEN(PhantomData<()>);

#[derive(Debug, Error)]
#[non_exhaustive]
/// Error types for callbacks
///
/// This error is designed to be useful to signal callback-specific states.
///
/// It does however additionally include hidden internal errors that are required for some
/// functionality but can not be handled by user code. Due to those this enum is marked
/// [`#[non_exhaustive]`](https://rust-lang.github.io/rfcs/2008-non-exhaustive.html) — in
/// practice this means that any match on the variant of `CallbackError` must include a catch-all
/// `_`.
///
/// So instead of
/// ```no_compile
/// # use rsasl::callback::CallbackError;
/// let callback_error: CallbackError;
/// # callback_error = CallbackError::NoCallback;
/// match callback_error {
///     CallbackError::NoValue => { /* handle NoValue case */ },
///     CallbackError::NoCallback => { /* handle NoCallback case */ },
/// }
/// ```
/// you must write:
/// ```rust
/// # use rsasl::callback::CallbackError;
/// let callback_error: CallbackError;
/// # callback_error = CallbackError::NoCallback("");
/// match callback_error {
///     CallbackError::NoValue => { /* handle NoValue case */ },
///     CallbackError::NoCallback(_) => { /* handle NoCallback case */ },
///     _ => {}, // skip if it's an internal error type that we can't work with.
/// }
/// ```
///
/// `From<CallbackError>` is implemented by [`SessionError`], so `callback` and other functions
/// returning `SessionError` can use this type directly with `?`:
///
/// ```rust
/// # use rsasl::callback::CallbackError;
/// # use rsasl::prelude::SessionError;
/// fn some_fn() -> Result<(), CallbackError> {
///     Err(CallbackError::NoValue)
/// }
///
/// fn callback() -> Result<(), SessionError> {
///     some_fn()?;
///     Ok(())
/// }
/// ```
pub enum CallbackError {
    #[error("callback could not provide a value for this query type")]
    NoValue,
    #[error("callback does not handle property {0}")]
    NoCallback(&'static str),

    #[doc(hidden)]
    #[error("callback issued early return")]
    EarlyReturn(TOKEN),
}
impl CallbackError {
    const fn early_return() -> Self {
        Self::EarlyReturn(TOKEN(PhantomData))
    }
    pub fn is_no_callback(&self) -> bool {
        match self {
            Self::NoCallback(_) => true,
            _ => false,
        }
    }
}

pub(crate) trait CallbackRequest<Answer: ?Sized> {
    fn satisfy(&mut self, answer: &Answer) -> Result<(), SessionError>;
}

enum ClosureCRState<F, G> {
    Open(F),
    Satisfied(G),
}
#[repr(transparent)]
pub(crate) struct ClosureCR<P, F, G> {
    closure: Option<ClosureCRState<F, G>>,
    _marker: PhantomData<P>,
}

impl<P, F, G> ClosureCR<P, F, G>
where
    P: for<'p> Property<'p>,
    F: FnOnce(&<P as Property<'_>>::Value) -> Result<G, SessionError>,
{
    pub fn wrap(closure: F) -> ClosureCR<P, F, G> {
        ClosureCR {
            closure: Some(ClosureCRState::Open(closure)),
            _marker: PhantomData,
        }
    }
    pub fn try_unwrap(self) -> Option<G> {
        if let Some(ClosureCRState::Satisfied(val)) = self.closure {
            Some(val)
        } else {
            None
        }
    }
}

impl<P, F, G> CallbackRequest<<P as Property<'_>>::Value> for ClosureCR<P, F, G>
where
    P: for<'p> Property<'p>,
    F: FnOnce(&<P as Property<'_>>::Value) -> Result<G, SessionError>,
{
    fn satisfy(&mut self, answer: &<P as Property<'_>>::Value) -> Result<(), SessionError> {
        if let Some(ClosureCRState::Open(mut closure)) = self.closure.take() {
            let reply = closure(answer)?;
            self.closure = Some(ClosureCRState::Satisfied(reply));
        }
        Ok(())
    }
}

#[repr(transparent)]
pub(crate) struct Satisfy<T>(PhantomData<T>);
impl<'a, T: Property<'a>> tags::MaybeSizedType<'a> for Satisfy<T> {
    type Reified = dyn CallbackRequest<T::Value> + 'a;
}

#[repr(transparent)]
pub(crate) struct Action<T>(PhantomData<T>);
impl<'a, T: Property<'a>> tags::Type<'a> for Action<T> {
    type Reified = Option<&'a T::Value>;
}

#[repr(transparent)]
/// A type-erased request for the value or action defined by [`Property`]
///
/// Requests can be either a 'Satisfiable' request for a value, in which case the methods
/// [`satisfy`](Request::satisfy) and [`satisfy_with`](Request::satisfy_with) can be used.
///
/// Alternatively they may be an 'Actionable' request, in which case
/// [`get_action`](Request::get_action) returns an associated value.
///
/// Whether a request is 'Actionable' or 'Satisfiable' depends on the property, mechanism and
/// side and is documented in the documentation of the mechanism implementation in question.
pub struct Request<'a>(dyn Erased<'a>);
impl<'a> Request<'a> {
    pub(crate) fn new_satisfy<P: for<'p> Property<'p>>(
        opt: &'a mut Tagged<'a, tags::RefMut<Satisfy<P>>>,
    ) -> &'a mut Self
    {
        unsafe { core::mem::transmute(opt as &mut dyn Erased) }
    }

    pub(crate) fn new_action<'t, 'p, P: Property<'p>>(
        val: &'t mut Tagged<'p, Action<P>>,
    ) -> &'t mut Self {
        unsafe { core::mem::transmute(val as &mut dyn Erased) }
    }
}
impl<'a> Request<'a> {
    fn is_satisfy<P: Property<'a>>(&self) -> bool {
        self.0.is::<tags::RefMut<Satisfy<P>>>()
    }
    fn is_action<P: Property<'a>>(&self) -> bool {
        self.0.is::<Action<P>>()
    }

    /// Returns true iff this Request is for the Property `P`.
    ///
    /// Using this method is generally not necessary as [`satisfy`](Request::satisfy),
    /// [`satisfy_with`](Request::satisfy_with) and [`get_action`](Request::get_action) can used
    /// efficiently without.
    pub fn is<P: Property<'a>>(&self) -> bool {
        self.is_satisfy::<P>() || self.is_action::<P>()
    }

    /// Get a reference to [the associated value](Property::Value) of an 'Actionable' Request for `P`.
    ///
    /// This method does not work for all requests, even if `Self::is` returned true for the
    /// given `P`, as 'Satisfiable' requests are instead **requesting** a value for `P`.
    ///
    /// `get_action` will return `None` if the request is not an `Actionable` request for the
    /// given `P`, or if called for the same `P` multiple times.
    ///
    /// ```rust
    /// # use rsasl::callback::Request;
    /// # use rsasl::prelude::SessionError;
    /// # use rsasl::property::{OpenID20AuthenticateInBrowser, Saml20AuthenticateInBrowser};
    /// # fn do_something(url: &str) {}
    /// # fn do_something_else(url: &str) {}
    /// # fn example(request: &mut Request) -> Result<(), SessionError> {
    /// // Since get_action returns `None` if P doesn't match, `if let` constructs are a nice way
    /// // to check for the different options
    /// if let Some(url) = request.get_action::<OpenID20AuthenticateInBrowser>() {
    ///     do_something(url);
    ///     return Ok(());
    /// }
    /// if let Some(url) = request.get_action::<Saml20AuthenticateInBrowser>() {
    ///     do_something_else(url);
    ///     return Ok(());
    /// }
    /// Ok(())
    /// # }
    /// ```
    pub fn get_action<P: Property<'a>>(&'a mut self) -> Option<&'a P::Value> {
        if let Some(Tagged(Some(value))) =
            self.0.downcast_mut::<Action<P>>().take()
        {
            Some(*value)
        } else {
            None
        }
    }

    #[must_use]
    /// Satisfy a 'Satisfiable' request using the provided value.
    ///
    /// If the type of the request is `P` and the request was not yet satisfied, this method
    /// will satisfy the request and return an opaque `Err` that must be bubbled up.
    ///
    /// If the request is not for the property `P`, already satisfied or not a 'Satisfiable'
    /// request this method will *always* return `Ok(&mut Self)`.
    ///
    /// This behaviour allows to easily chain multiple calls using the `?` operator:
    ///
    /// ```rust
    /// # use rsasl::callback::Request;
    /// # use rsasl::prelude::SessionError;
    /// # use rsasl::property::{AuthId, AuthzId, Password};
    /// # fn example(request: &mut Request<'_>) -> Result<(), SessionError> {
    /// request
    ///     .satisfy::<AuthId>("authid")? // if `P` is AuthId this will immediately return
    ///     .satisfy::<Password>(b"password")?
    ///     // It's important that errors are returned so the last call should have a `?` too.
    ///     .satisfy::<AuthzId>("authzid")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # faulty use of `satisfy`/`satisfy_with`
    ///
    /// It's important to note that calls will succeed if the request is **not for this property**.
    /// Thus care must be taken when satisfying requests to prevent bugs:
    ///
    /// ```should_panic
    /// # use rsasl::callback::Request;
    /// # use rsasl::prelude::SessionError;
    /// # use rsasl::property::{AuthId, AuthzId, Password};
    /// # fn ask_user_for_password<'a>() -> Result<&'a [u8], SessionError> { Ok(&[]) }
    /// # fn try_get_cached_password<'a>() -> Option<&'a [u8]> { Some(&[]) }
    /// # fn example(request: &mut Request<'_>) -> Result<(), SessionError> {
    /// if let Some(password) = try_get_cached_password() {
    ///     request.satisfy::<Password>(password)?;
    ///     // This is wrong, as the above call will *succeed* if `AuthId` was requested but this
    ///     // return may prevent the `satisfy` below from ever being evaluated.
    ///     return Ok(());
    /// }
    /// request.satisfy_with::<Password, _>(|| ask_user_for_password())?;
    /// request.satisfy::<AuthId>("foobar")?;
    /// # Ok(())
    /// # }
    /// # panic!("request for 'AuthId' is implemented but was not satisfied");
    /// ```
    ///
    /// If generating the value is expensive or requires interactivity using the method
    /// [`satisfy_with`](Request::satisfy_with) may be preferable.
    pub fn satisfy<P: Property<'a>>(&mut self, answer: &P::Value)
        -> Result<&mut Self, SessionError>
    {
        if let Some(Tagged(mech)) = self.0.downcast_mut::<tags::RefMut<Satisfy<P>>>() {
            mech.satisfy(answer)?;
            Err(CallbackError::early_return().into())
        } else {
            Ok(self)
        }
    }

    #[must_use]
    /// Satisfy a 'Satisfiable' request using the provided closure.
    ///
    /// If the type of the request is `P` and the request was not yet satisfied, this method
    /// will evaluate the closure and satisfy the request, returning an opaque `Err` that must be
    /// bubbled up.
    ///
    /// If the request is not for the property `P`, already satisfied or not a 'Satisfiable'
    /// request this method will is guaranteed to not evaluate the provided closure and return an
    /// `Ok(&mut Self)`.
    ///
    /// This behaviour allows to easily chain multiple calls using the `?` operator:
    ///
    /// ```rust
    /// # use rsasl::callback::Request;
    /// # use rsasl::prelude::SessionError;
    /// # use rsasl::property::{AuthId, AuthzId, Password};
    /// # fn ask_user_for_authid<'a>() -> Result<&'a str, SessionError> { unimplemented!() }
    /// # fn ask_user_for_password<'a>() -> Result<&'a [u8], SessionError> { unimplemented!() }
    /// # fn try_get_cached_password<'a>() -> Option<&'a [u8]> { unimplemented!() }
    /// # fn example(request: &mut Request<'_>) -> Result<(), SessionError> {
    /// // Skipping the interactive asking if the password was cached previously
    /// if let Some(password) = try_get_cached_password() {
    ///     // Several calls for satisfy may exist, but only the first value set will ever be used.
    ///     request.satisfy::<Password>(password)?;
    /// }
    ///
    /// request
    ///     .satisfy_with::<AuthId, _>(|| ask_user_for_authid())?
    ///     .satisfy_with::<Password, _>(|| ask_user_for_password())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # faulty use of `satisfy`/`satisfy_with`
    ///
    /// It's important to note that calls will succeed if the request is **not for this property**.
    /// Thus care must be taken when satisfying requests to prevent bugs:
    ///
    /// ```should_panic
    /// # use rsasl::callback::Request;
    /// # use rsasl::prelude::SessionError;
    /// # use rsasl::property::{AuthId, AuthzId, Password};
    /// # fn ask_user_for_password<'a>() -> Result<&'a [u8], SessionError> { Ok(&[]) }
    /// # fn try_get_cached_password<'a>() -> Option<&'a [u8]> { Some(&[]) }
    /// # fn example(request: &mut Request<'_>) -> Result<(), SessionError> {
    /// if let Some(password) = try_get_cached_password() {
    ///     request.satisfy::<Password>(password)?;
    ///     // This is wrong, as the above call will *succeed* if `AuthId` was requested but this
    ///     // return may prevent the `satisfy` below from ever being evaluated.
    ///     return Ok(());
    /// }
    /// request.satisfy_with::<Password, _>(|| ask_user_for_password())?;
    /// request.satisfy::<AuthId>("foobar")?;
    /// # Ok(())
    /// # }
    /// # panic!("request for 'AuthId' is implemented but was not satisfied");
    /// ```
    ///
    /// If the value for a property is static or readily available using
    /// [`satisfy`](Request::satisfy) may be preferable.
    pub fn satisfy_with<P: Property<'a>, F: FnOnce() -> Result<&'a P::Value, SessionError>>(
        &'a mut self,
        closure: F,
    ) -> Result<&'a mut Self, SessionError> {
        if let Some(Tagged(mech)) = self.0.downcast_mut::<tags::RefMut<Satisfy<P>>>() {
            let answer = closure()?;
            mech.satisfy(answer)?;
            Err(CallbackError::early_return().into())
        } else {
            Ok(self)
        }
    }
}