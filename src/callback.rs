//! User-provided callbacks
//!
//! Make very generic data go from user to mechanism and vice versa through the protocol impl
//! that should not need to care about the shape of this data.
//! Yeah, *all* the runtime reflection.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;

pub use crate::context::Context;
use crate::error::SessionError;
use crate::property::Property;

use crate::session::SessionData;
use crate::typed::{tags, Erased, TaggedOption};
use crate::validate::{Validate, ValidationError};

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
    /// # use rsasl::callback::{Request, SessionCallback, Context};
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
        request: &mut Request<'_>,
    ) -> Result<(), SessionError> {
        let _ = (session_data, context, request);
        Err(CallbackError::NoCallback.into())
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
        let _ = (session_data, context, validate);
        Ok(())
    }
}

#[derive(Debug)]
// todo: Have a "I would handle this but I have no value valid with the *given context*" (e.g.
//       User with that authid isn't found in the db)
// todo: impl From<Box<E>>
pub enum CallbackError {
    NoCallback,
    Boxed(Box<dyn Error + Send + Sync>),

    #[doc(hidden)]
    EarlyReturn(PhantomData<()>),
}
impl CallbackError {
    pub fn is_no_callback(&self) -> bool {
        match self {
            Self::NoCallback => true,
            _ => false,
        }
    }
}
impl Display for CallbackError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CallbackError::NoCallback => f.write_str("Callback does not handle that query type"),
            CallbackError::Boxed(e) => Display::fmt(e, f),
            CallbackError::EarlyReturn(_) => f.write_str("callback returned early"),
        }
    }
}
impl Error for CallbackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            CallbackError::Boxed(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

pub(crate) trait CallbackRequest<Answer: ?Sized> {
    fn satisfy(&mut self, answer: &Answer) -> Result<(), SessionError>;
}

enum ClosureCRState<'f, F, G> {
    Open(&'f mut F),
    Satisfied(G),
}
#[repr(transparent)]
pub(crate) struct ClosureCR<'f, T, F, G> {
    closure: ClosureCRState<'f, F, G>,
    _marker: PhantomData<T>,
}
impl<'f, T, F, G> ClosureCR<'f, T, F, G>
where
    T: Property,
    F: FnMut(&T::Value) -> Result<G, SessionError>,
{
    pub fn wrap(closure: &'f mut F) -> ClosureCR<'f, T, F, G> {
        ClosureCR {
            closure: ClosureCRState::Open(closure),
            _marker: PhantomData,
        }
    }
    pub fn try_unwrap(self) -> Option<G> {
        if let ClosureCRState::Satisfied(val) = self.closure {
            Some(val)
        } else {
            None
        }
    }
}
impl<T, F, G> CallbackRequest<T::Value> for ClosureCR<'_, T, F, G>
where
    T: Property,
    F: FnMut(&T::Value) -> Result<G, SessionError>,
{
    fn satisfy(&mut self, answer: &T::Value) -> Result<(), SessionError> {
        if let ClosureCRState::Open(closure) = &mut self.closure {
            let reply = closure(answer)?;
            let _ = std::mem::replace(&mut self.closure, ClosureCRState::Satisfied(reply));
        }
        Ok(())
    }
}

#[repr(transparent)]
pub(crate) struct Satisfy<T>(PhantomData<T>);
impl<'a, T: Property> tags::MaybeSizedType<'a> for Satisfy<T> {
    type Reified = dyn CallbackRequest<T::Value> + 'a;
}

#[repr(transparent)]
pub(crate) struct Action<T>(PhantomData<T>);
impl<'a, T: Property> tags::MaybeSizedType<'a> for Action<T> {
    type Reified = T::Value;
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
    pub(crate) fn new_satisfy<'o, P: Property>(
        opt: &'o mut TaggedOption<'a, tags::RefMut<Satisfy<P>>>,
    ) -> &'o mut Self {
        unsafe { std::mem::transmute(opt as &mut dyn Erased) }
    }

    pub(crate) fn new_action<'o, P: Property>(
        val: &'o mut TaggedOption<'a, tags::Ref<Action<P>>>,
    ) -> &'o mut Self {
        unsafe { std::mem::transmute(val as &mut dyn Erased) }
    }
}
impl<'a> Request<'a> {
    fn is_satisfy<P: Property>(&self) -> bool {
        self.0.is::<tags::RefMut<Satisfy<P>>>()
    }
    fn is_action<P: Property>(&self) -> bool {
        self.0.is::<tags::Ref<Action<P>>>()
    }

    /// Returns true iff this Request is for the Property `P`.
    ///
    /// Using this method is generally not necessary as [`satisfy`](Request::satisfy),
    /// [`satisfy_with`](Request::satisfy_with) and [`get_action`](Request::get_action) can used
    /// efficiently without.
    pub fn is<P: Property>(&self) -> bool {
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
    pub fn get_action<P: Property>(&mut self) -> Option<&P::Value> {
        if let Some(TaggedOption(Some(value))) =
            self.0.downcast_mut::<tags::Ref<Action<P>>>().take()
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
    /// # fn ask_user_for_password<'a>() -> &'a [u8] { &[] }
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
    pub fn satisfy<P: Property>(&mut self, answer: &P::Value) -> Result<&mut Self, SessionError> {
        if let Some(TaggedOption(Some(mech))) = self.0.downcast_mut::<tags::RefMut<Satisfy<P>>>() {
            mech.satisfy(answer)?;
            Err(CallbackError::EarlyReturn(PhantomData).into())
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
    /// # fn ask_user_for_authid<'a>() -> &'a str { unimplemented!() }
    /// # fn ask_user_for_password<'a>() -> &'a [u8] { unimplemented!() }
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
    /// # fn ask_user_for_password<'a>() -> &'a [u8] { &[] }
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
    pub fn satisfy_with<'b, P: Property, F: FnOnce() -> &'b P::Value>(
        &mut self,
        closure: F,
    ) -> Result<&mut Self, SessionError> {
        if let Some(TaggedOption(Some(mech))) = self.0.downcast_mut::<tags::RefMut<Satisfy<P>>>() {
            let answer = closure();
            mech.satisfy(answer)?;
            Err(CallbackError::EarlyReturn(PhantomData).into())
        } else {
            Ok(self)
        }
    }
}

pub struct EmptyCallback;
impl SessionCallback for EmptyCallback {}
