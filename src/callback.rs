//! User-provided callbacks
//!
//! Make very generic data go from user to mechanism and vice versa through the protocol impl
//! that should not need to care about the shape of this data.
//! Yeah, *all* the runtime reflection.
//!
//! ## Why not just return the requested value from a callback?
//! Because that would devolve to basically `fn callback(query: Box<dyn Any>) -> Box<dyn Any>`
//! with exactly zero protection against accidentally not providing some required data.

use crate::callback::tags::MaybeSizedType;
use std::any::TypeId;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;

use crate::session::SessionData;
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

pub mod tags {
    use std::marker::PhantomData;

    pub trait Type<'a>: 'static + Sized {
        type Reified: 'a;
    }

    pub trait MaybeSizedType<'a>: 'static + Sized {
        type Reified: 'a + ?Sized;
    }
    impl<'a, T: Type<'a>> MaybeSizedType<'a> for T {
        type Reified = T::Reified;
    }

    pub struct Value<T: 'static>(PhantomData<T>);
    impl<'a, T: 'static> Type<'a> for Value<T> {
        type Reified = T;
    }

    pub struct MaybeSizedValue<T: 'static + ?Sized>(PhantomData<T>);
    impl<'a, T: 'static + ?Sized> MaybeSizedType<'a> for MaybeSizedValue<T> {
        type Reified = T;
    }

    pub struct Ref<T>(PhantomData<T>);
    impl<'a, T: MaybeSizedType<'a>> Type<'a> for Ref<T> {
        type Reified = &'a T::Reified;
    }

    pub struct RefMut<T>(PhantomData<T>);
    impl<'a, T: MaybeSizedType<'a>> Type<'a> for RefMut<T> {
        type Reified = &'a mut T::Reified;
    }
}

#[repr(transparent)]
pub(crate) struct RequestTag<T>(PhantomData<T>);
impl<'a, T: tags::MaybeSizedType<'a>> MaybeSizedType<'a> for RequestTag<T> {
    type Reified = dyn CallbackRequest<T::Reified> + 'a;
}

pub trait CallbackRequest<Answer: ?Sized> {
    fn satisfy(&mut self, answer: &Answer);
}

#[repr(transparent)]
pub struct ClosureCR<'a, T, F: 'a> {
    closure: F,
    _marker: PhantomData<&'a T>,
}
impl<'a, T, F> ClosureCR<'a, T, F>
where
    T: tags::MaybeSizedType<'a>,
    F: FnMut(&T::Reified) + 'a,
{
    pub fn wrap(closure: &mut F) -> &mut Self {
        unsafe { std::mem::transmute(closure) }
    }
}
impl<'a, T, F> CallbackRequest<T::Reified> for ClosureCR<'a, T, F>
where
    T: tags::MaybeSizedType<'a>,
    F: FnMut(&T::Reified),
{
    fn satisfy(&mut self, answer: &T::Reified) {
        (self.closure)(answer)
    }
}

trait Erased<'a>: 'a {
    fn tag_id(&self) -> TypeId;
}
impl<'a> dyn Erased<'a> {
    #[inline]
    fn is<T: tags::Type<'a>>(&self) -> bool {
        TypeId::of::<T>() == self.tag_id()
    }

    #[inline]
    fn downcast_mut<T: tags::Type<'a>>(&mut self) -> Option<&mut TaggedOption<'a, T>> {
        if self.is::<T>() {
            Some(unsafe { &mut *(self as *mut Self as *mut TaggedOption<'a, T>) })
        } else {
            None
        }
    }
}

#[repr(transparent)]
pub(crate) struct TaggedOption<'a, T: tags::Type<'a>>(pub(crate) Option<T::Reified>);
impl<'a, T: tags::Type<'a>> Erased<'a> for TaggedOption<'a, T> {
    fn tag_id(&self) -> TypeId {
        TypeId::of::<T>()
    }
}
impl<'a, T: tags::Type<'a>> TaggedOption<'a, T> {
    pub fn is_some(&self) -> bool {
        self.0.is_some()
    }

    unsafe fn as_demand(&mut self) -> &mut Demand<'a> {
        std::mem::transmute(self as &mut dyn Erased)
    }

    pub(crate) unsafe fn as_request(&mut self) -> &mut Request<'a> {
        std::mem::transmute(self as &mut dyn Erased)
    }

    pub(crate) unsafe fn as_validate(&mut self) -> &mut Validate<'a> {
        std::mem::transmute(self as &mut dyn Erased)
    }

    pub fn take(&mut self) -> Option<T::Reified> {
        self.0.take()
    }
}

#[repr(transparent)]
pub struct Demand<'a>(dyn Erased<'a> + 'a);
impl<'a> Demand<'a> {
    fn provide<T: tags::Type<'a>>(&mut self, value: T::Reified) -> &mut Self {
        if let Some(res @ TaggedOption(None)) = self.0.downcast_mut::<T>() {
            res.0 = Some(value)
        }
        self
    }
    fn provide_with<T: tags::Type<'a>, F: FnOnce() -> T::Reified>(&mut self, f: F) -> &mut Self {
        if let Some(res @ TaggedOption(None)) = self.0.downcast_mut::<T>() {
            res.0 = Some(f())
        }
        self
    }

    pub fn provide_ref<T: tags::MaybeSizedType<'a>>(&mut self, value: &'a T::Reified) -> &mut Self {
        self.provide::<tags::Ref<T>>(value)
    }
    pub fn provide_value<T: tags::Type<'a>, F: FnOnce() -> T::Reified>(
        &mut self,
        f: F,
    ) -> &mut Self {
        self.provide_with::<T, F>(f)
    }
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
    pub fn satisfy<T: tags::MaybeSizedType<'a>>(&mut self, answer: &T::Reified) -> Option<()> {
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

pub trait Provider<'a> {
    fn provide(&'a self, req: &mut Demand<'a>);
}
impl<'a> Provider<'a> for () {
    fn provide(&'a self, _: &mut Demand<'a>) {}
}
#[repr(transparent)]
pub struct ThisProvider<'a, T: tags::MaybeSizedType<'a>>(&'a T::Reified);
impl<'a, T: tags::MaybeSizedType<'a>> ThisProvider<'a, T> {
    pub fn with(value: &'a T::Reified) -> Self {
        Self(value)
    }
}
impl<'a, T: tags::MaybeSizedType<'a>> Provider<'a> for ThisProvider<'a, T> {
    fn provide(&'a self, req: &mut Demand<'a>) {
        req.provide_ref::<T>(self.0);
    }
}

pub(crate) fn build_context<'a>(provider: &'a dyn Provider<'a>) -> &'a Context<'a> {
    unsafe { std::mem::transmute(provider) }
}

#[repr(transparent)]
pub struct Context<'a>(dyn Provider<'a>);
impl<'a> Context<'a> {
    fn get_by_tag<T: tags::Type<'a>>(&'a self) -> Option<T::Reified> {
        let mut tagged_option = TaggedOption::<'a, T>(None);
        self.0.provide(unsafe { tagged_option.as_demand() });
        tagged_option.0
    }
    pub fn get_ref<T: tags::MaybeSizedType<'a>>(&'a self) -> Option<&'a T::Reified> {
        self.get_by_tag::<tags::Ref<T>>()
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
        context: &Context<'_>,
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
        context: &Context<'_>,
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
