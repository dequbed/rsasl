//! User-provided callbacks
//!
//! Make very generic data go from user to mechanism and vice versa through the protocol impl
//! that should not need to care about the shape of this data.
//! Yeah, *all* the runtime reflection.
//!
//! ## Why not just return the requested value from a callback?
//! Because that would devolve to basically `fn callback(query: Box<dyn Any>) -> Box<dyn Any>`
//! with exactly zero type-level protection against accidentally not providing some required data.

use std::any::TypeId;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use crate::context::Context;
use crate::property::MaybeSizedProperty;

use crate::session::SessionData;
use crate::typed::tags;
use crate::validate::Validation;

#[derive(Debug)]
pub enum CallbackError {
    NoCallback,
    NoAnswer,
    Boxed(Box<dyn Error + Send + Sync>),
}
impl Display for CallbackError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CallbackError::NoCallback => f.write_str("Callback does not handle that query type"),
            CallbackError::NoAnswer => f.write_str("Callback failed to provide an answer"),
            CallbackError::Boxed(e) => Display::fmt(e, f),
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
impl<'a, T, F> ClosureCR<T, F>
where
    T: tags::MaybeSizedType<'a>,
    F: FnMut(&T::Reified),
{
    pub fn wrap(closure: &mut F) -> &mut Self {
        unsafe { std::mem::transmute(closure) }
    }
}
impl<'a, T, F> CallbackRequest<T::Reified> for ClosureCR<T, F>
where
    T: tags::MaybeSizedType<'a>,
    F: FnMut(&T::Reified),
{
    fn satisfy(&mut self, answer: &T::Reified) {
        (self.closure)(answer)
    }
}


#[repr(transparent)]
struct RequestTag<T>(PhantomData<T>);
impl<'a, T: MaybeSizedProperty> tags::MaybeSizedType<'a> for RequestTag<T> {
    type Reified = dyn CallbackRequest<T::Value> + 'a;
}


#[repr(transparent)]
/// A type-erased callback request for some potentially context-specific values.
///
/// Since the actual type of the request is erased callbacks must first specify a type when
/// wanting to satisfy the request. This is done with the type parameter `T` on the
/// [`satisfy_with`] method.
pub struct Request<'a>(dyn Erased<'a>);
impl<'a> Request<'a> {
    /// Return true if the Request is of type `T`.
    ///
    pub fn is<T: tags::MaybeSizedType<'a>>(&self) -> bool {
        self.0.is::<tags::RefMut<RequestTag<T>>>()
    }

    /// Satisfy the given Request type `T` using the provided closure.
    ///
    /// If the type of the request is not `T` or if the request was already satisfied this method
    /// returns `None`.
    pub fn satisfy<T: tags::MaybeSizedType<'a>>(&mut self, answer: &'a T::Reified) -> Option<
        ()> {
        if let Some(mech) = self
            .0
            .downcast_mut::<tags::RefMut<RequestTag<T>>>()
            .and_then(TaggedOption::take)
        {
            Some(mech.satisfy(answer))
        } else {
            None
        }
    }
}


#[repr(transparent)]
// TODO:
//  Validate should be used to be able to do the final check on the authentication, either
//  accepting or denying it. So it should have a method that is in some ways mandatory to call.
pub struct Validate<'a>(dyn Erased<'a>);
impl<'a> Validate<'a> {
    #[inline(always)]
    pub fn is<T: Validation<'a>>(&self) -> bool {
        self.0.tag_id() == TypeId::of::<T>()
    }

    pub fn finalize<T: Validation<'a>>(&mut self, outcome: T::Reified) -> &mut Self {
        if let Some(result @ TaggedOption(None)) = self.0.downcast_mut::<T>() {
            *result = TaggedOption(Some(outcome))
        }
        self
    }
}

#[derive(Debug)]
pub enum ValidationError {
    NoValidation,
    BadAuthentication,
    BadAuthorization,
}

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
    /// fn callback(&self, session: &SessionData, context: &Context<'_>, request: &mut Request<'_>)
    ///     -> Result<(), CallbackError>
    /// {
    ///     if request.is::<AuthId>() {
    ///         request.satisfy("exampleuser");
    ///         Ok(())
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
        session_data: &SessionData,
        context: &Context,
        request: &mut Request<'_>,
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
        session_data: &SessionData,
        context: &Context,
        validate: &mut Validate<'_>,
    ) -> Result<(), ValidationError> {
        Err(ValidationError::NoValidation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mechanisms::plain::server::PlainValidation;
    use std::ptr::NonNull;

    #[test]
    fn test_thisprovider() {
        struct TestTag;
        impl<'a> tags::Type<'a> for TestTag {
            type Reified = &'a str;
        }
        let value = "hello!";
        let p = ThisProvider::<TestTag>::with(&value);
        let ctx = build_context(&p);
        assert_eq!(ctx.get_ref::<TestTag>().unwrap(), &"hello!");
    }
}
