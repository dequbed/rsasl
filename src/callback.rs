//! User-provided callbacks
//!
//! Make very generic data go from user to mechanism and vice versa through the protocol impl
//! that should not need to care about the shape of this data.
//! Yeah, *all* the runtime reflection.
//!
//! ## Why not just return the requested value from a callback?
//! Because that would devolve to basically `fn callback(query: Box<dyn Any>) -> Box<dyn Any>`
//! with exactly zero type-level protection against accidentally not providing some required data.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;

use crate::context::Context;
use crate::property::MaybeSizedProperty;

use crate::session::SessionData;
use crate::typed::{tags, Erased, TaggedOption};
use crate::validate::{Validate, ValidationError};

pub trait SessionCallback {
    /// Query by a mechanism implementation to provide some information or do some action
    ///
    /// The parameter `query` defines the exact property that is requested. Query is a request for
    /// either some information ("property"), or to perform some outside action (e.g. authenticate
    /// with the users IdP).
    ///
    /// In most cases a
    /// callback should then issue a call to [`SessionData::set_property`], so e.g.
    /// ```rust
    /// # use std::sync::Arc;
    /// # use rsasl::callback::{Callback, Context, Request, CallbackError};
    /// # use rsasl::Property;
    /// use rsasl::property::{properties, Password, CallbackQ, AuthId};
    /// # use rsasl::session::SessionData;
    /// # struct CB;
    /// # impl Callback for CB {
    /// fn callback(&self, session: &SessionData, context: &Context, request: &mut Request<'_>)
    ///     -> Result<(), CallbackError>
    /// {
    ///     if request.is::<AuthId>() {
    ///         Ok(request.satisfy("exampleuser"))
    ///     } else {
    ///         Err(CallbackError::NoCallback)
    ///     }
    /// }
    /// # }
    /// ```
    ///
    /// In some cases (e.g. [`OpenID20AuthenticateInBrowser`] the mechanism expects that a certain
    /// action is taken by the user instead of an explicit property being provided (e.g. to
    /// authenticate to their OIDC IdP using the system's web browser).
    fn callback(
        &self,
        _session_data: &SessionData,
        _context: &Context,
        _request: &mut Request<'_>,
    ) -> Result<(), CallbackError> {
        Err(CallbackError::NoCallback)
    }

    /// Validate an authentication exchange
    ///
    /// This callback will mostly be issued on the server side of an authentication exchange to
    /// validate the data passed in by the client side like username/password for `PLAIN`.
    ///
    fn validate(
        &self,
        _session_data: &SessionData,
        _context: &Context,
        _validate: &mut Validate<'_>,
    ) -> Result<(), ValidationError> {
        Err(ValidationError::NoValidation)
    }
}

#[derive(Debug)]
pub enum CallbackError {
    NoCallback,
    NoAnswer,
    Boxed(Box<dyn Error + Send + Sync>),

    #[doc(hidden)]
    EarlyReturn(PhantomData<()>),
}
impl Display for CallbackError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CallbackError::NoCallback => f.write_str("Callback does not handle that query type"),
            CallbackError::NoAnswer => f.write_str("Callback failed to provide an answer"),
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

pub trait CallbackRequest<Answer: ?Sized> {
    fn satisfy(&mut self, answer: &Answer);
}

#[repr(transparent)]
pub struct ClosureCR<T, F> {
    closure: F,
    _marker: PhantomData<T>,
}
impl<T, F> ClosureCR<T, F>
where
    T: MaybeSizedProperty,
    F: FnMut(&T::Value),
{
    pub fn wrap(closure: &mut F) -> &mut Self {
        unsafe { std::mem::transmute(closure) }
    }
}
impl<T, F> CallbackRequest<T::Value> for ClosureCR<T, F>
where
    T: MaybeSizedProperty,
    F: FnMut(&T::Value),
{
    fn satisfy(&mut self, answer: &T::Value) {
        (self.closure)(answer)
    }
}

#[repr(transparent)]
pub(crate) struct RequestTag<T>(PhantomData<T>);
impl<'a, T: MaybeSizedProperty> tags::MaybeSizedType<'a> for RequestTag<T> {
    type Reified = dyn CallbackRequest<T::Value> + 'a;
}

#[repr(transparent)]
///
/// A type-erased callback request for some potentially context-specific values.
/// Since the actual type of the request is erased callbacks must first specify a type when
/// wanting to satisfy the request. This is done with the type parameter `T` on the
/// [`satisfy_with`] method.
pub struct Request<'a>(dyn Erased<'a>);
impl<'a> Request<'a> {
    pub(crate) fn new<'o, P: MaybeSizedProperty>(
        opt: &'o mut TaggedOption<'a, tags::RefMut<RequestTag<P>>>,
    ) -> &'o mut Self {
        unsafe { std::mem::transmute(opt as &mut dyn Erased) }
    }
}
impl<'a> Request<'a> {
    /// Return true if the Request is of type `P`.
    ///
    pub fn is<P: MaybeSizedProperty>(&self) -> bool {
        self.0.is::<tags::RefMut<RequestTag<P>>>()
    }

    /// Satisfy the given Request type `P` using the provided closure.
    ///
    /// # Shortcutting behaviour
    /// Iff the type of the request is `P` and the request was not yet satisfied, this method
    /// will return an `Err`, otherwise it will return `Ok(&mut Self)`. This behaviour allows to
    /// easily chain multiple calls to `satisfy` but shortcutting on the first successful one:
    ///
    /// ```rust
    /// # use rsasl::callback::{CallbackError, Request};
    /// # use rsasl::property::{AuthId, Password};
    /// # fn example(request: &mut Request<'_>) -> Result<(), CallbackError> {
    /// request
    ///     .satisfy::<AuthId>("authid")? // if `P` is AuthId this will immediately return
    ///     .satisfy::<Password>(b"password")?
    ///     .satisfy::<Authzid>("authzid")?;
    /// Ok(()) // If no error occured, but the request was also not satisfied,
    /// # }
    /// ```
    pub fn satisfy<P: MaybeSizedProperty>(
        &mut self,
        answer: &P::Value,
    ) -> Result<&mut Self, CallbackError> {
        if let Some(TaggedOption(Some(mech))) =
            self.0.downcast_mut::<tags::RefMut<RequestTag<P>>>().take()
        {
            mech.satisfy(answer);
            Err(CallbackError::EarlyReturn(PhantomData))
        } else {
            Ok(self)
        }
    }
}
