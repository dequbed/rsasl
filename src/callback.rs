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
use crate::error::SessionError;
use crate::property::MaybeSizedProperty;

use crate::session::SessionData;
use crate::typed::{tags, Erased, TaggedOption};
use crate::validate::{Validate, ValidationError};

pub trait SessionCallback {
    /// Query by a mechanism implementation to provide some information or do some action
    ///
    /// ```rust
    /// # use rsasl::callback::{Request, SessionCallback};
    /// # use rsasl::context::Context;
    /// # use rsasl::error::SessionError;
    /// # use rsasl::property::{AuthId, Password, AuthzId, OpenID20AuthenticateInBrowser, Realm};
    /// # use rsasl::session::SessionData;
    /// # struct CB;
    /// # fn open_browser_and_go_to(url: &str) { }
    /// # impl SessionCallback for CB {
    /// fn callback(&self, session: &SessionData, context: &Context, request: &mut Request<'_>)
    ///     -> Result<(), SessionError>
    /// {
    ///     // Some requests are to provide a value for the given property by calling `satisfy`.
    ///     request
    ///         // satisfy calls can be chained, making use of short-circuiting
    ///         .satisfy::<AuthId>("exampleuser")?
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
    /// In some cases (e.g. [`OpenID20AuthenticateInBrowser`] the mechanism expects that a certain
    /// action is taken by the user instead of an explicit property being provided (e.g. to
    /// authenticate to their OIDC IdP using the system's web browser).
    fn callback(
        &self,
        _session_data: &SessionData,
        _context: &Context,
        _request: &mut Request<'_>,
    ) -> Result<(), SessionError> {
        Err(CallbackError::NoCallback.into())
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
        Ok(())
    }
}

#[derive(Debug)]
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

pub trait CallbackRequest<Answer: ?Sized> {
    fn satisfy(&mut self, answer: &Answer) -> Result<(), SessionError>;
}


enum ClosureCRState<'f, F, G> {
    Open(&'f mut F),
    Satisfied(G)
}
#[repr(transparent)]
pub struct ClosureCR<'f, T, F, G> {
    closure: ClosureCRState<'f, F, G>,
    _marker: PhantomData<T>,
}
impl<'f, T, F, G> ClosureCR<'f, T, F, G>
where
    T: MaybeSizedProperty,
    F: FnMut(&T::Value) -> Result<G, SessionError>,
{
    pub fn wrap(closure: &'f mut F) -> ClosureCR<'f, T, F, G>
    {
        ClosureCR { closure: ClosureCRState::Open(closure), _marker: PhantomData }
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
    T: MaybeSizedProperty,
    F: FnMut(&T::Value) -> Result<G, SessionError>,
{
    fn satisfy(&mut self, answer: &T::Value) -> Result<(), SessionError> {
        if let ClosureCRState::Open(closure) = &mut self.closure {
            let reply = closure(answer)?;
            std::mem::replace(&mut self.closure, ClosureCRState::Satisfied(reply));
        }
        Ok(())
    }
}

#[repr(transparent)]
pub(crate) struct Satisfy<T>(PhantomData<T>);
impl<'a, T: MaybeSizedProperty> tags::MaybeSizedType<'a> for Satisfy<T> {
    type Reified = dyn CallbackRequest<T::Value> + 'a;
}

#[repr(transparent)]
pub(crate) struct Action<T>(PhantomData<T>);
impl<'a, T: MaybeSizedProperty> tags::MaybeSizedType<'a> for Action<T> {
    type Reified = T::Value;
}

#[repr(transparent)]
/// A type-erased callback request for some potentially context-specific values.
///
/// Since the actual type of the request is erased callbacks must first specify a type when
/// wanting to satisfy the request. This is done with the type parameter `T` on the
/// [`satisfy_with`] method.
pub struct Request<'a>(dyn Erased<'a>);
impl<'a> Request<'a> {
    pub(crate) fn new_satisfy<'o, P: MaybeSizedProperty>(
        opt: &'o mut TaggedOption<'a, tags::RefMut<Satisfy<P>>>,
    ) -> &'o mut Self {
        unsafe { std::mem::transmute(opt as &mut dyn Erased) }
    }

    pub(crate) fn new_action<'o, P: MaybeSizedProperty>(
        val: &'o mut TaggedOption<'a, tags::Ref<Action<P>>>,
    ) -> &'o mut Self {
        unsafe { std::mem::transmute(val as &mut dyn Erased) }
    }
}
impl<'a> Request<'a> {
    fn is_satisfy<P: MaybeSizedProperty>(&self) -> bool {
        self.0.is::<tags::RefMut<Satisfy<P>>>()
    }
    fn is_action<P: MaybeSizedProperty>(&self) -> bool {
        self.0.is::<tags::Ref<Action<P>>>()
    }

    /// Returns true iff this Request is for the Property `P`.
    ///
    /// Properties can be either requests to provide an appropriate value, or to perform a
    /// specific (usually sideband) action, e.g. opening a web browser and letting the user log
    /// in to their OpenID Connect / SAML / OAuth2 SSO-system.
    ///
    pub fn is<P: MaybeSizedProperty>(&self) -> bool {
        self.is_satisfy::<P>() || self.is_action::<P>()
    }

    /// Get a reference to the value of a Request `P`.
    ///
    /// This method does not work for all Requests, even if `Self::is` returned true for the
    /// same `P`, as e.g. a request to provide an Authentication ID can't return a reference to
    /// an value that wasn't provided yet.
    ///
    /// Refer to the documentation of a property on how to handle requests regarding it and whether
    /// it will generate actionable or satisfiable requests.
    pub fn get_action<P: MaybeSizedProperty>(&self) -> Option<&P::Value> {
        if let Some(TaggedOption(Some(value))) = self.0.downcast_ref::<tags::Ref<Action<P>>>() {
            Some(*value)
        } else {
            None
        }
    }

    /// Satisfy the given Request type `P` using the provided closure.
    ///
    /// # Shortcutting behaviour
    /// Iff the type of the request is `P` and the request was not yet satisfied, this method
    /// will return an `Err`, otherwise it will return `Ok(&mut Self)`. This behaviour allows to
    /// easily chain multiple calls to `satisfy` but shortcutting on the first successful one:
    ///
    /// ```rust
    /// # use rsasl::callback::Request;
    /// # use rsasl::error::SessionError;
    /// # use rsasl::property::{AuthId, AuthzId, Password};
    /// # fn example(request: &mut Request<'_>) -> Result<(), SessionError> {
    /// request
    ///     .satisfy::<AuthId>("authid")? // if `P` is AuthId this will immediately return
    ///     .satisfy::<Password>(b"password")?
    ///     .satisfy::<AuthzId>("authzid")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn satisfy<P: MaybeSizedProperty>(
        &mut self,
        answer: &P::Value,
    ) -> Result<&mut Self, SessionError> {
        if let Some(TaggedOption(Some(mech))) =
            self.0.downcast_mut::<tags::RefMut<Satisfy<P>>>()
        {
            mech.satisfy(answer)?;
            Err(CallbackError::EarlyReturn(PhantomData).into())
        } else {
            Ok(self)
        }
    }
}

pub struct EmptyCallback;
impl SessionCallback for EmptyCallback {

}