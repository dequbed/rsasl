//! User-provided callbacks
//!
//! Make very generic data go from user to mechanism and vice versa through the protocol impl
//! that should not need to care about the shape of this data.
//! Yeah, *all* the runtime reflection.
//!
//! ## Why not just return the requested value from a callback?
//! Because that would devolve to basically `fn callback(query: Box<dyn Any>) -> Box<dyn Any>`
//! with exactly zero protection against accidentally not providing some required data.

use std::any::TypeId;
use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::session::SessionData;

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

mod tags {
    use std::marker::PhantomData;

    pub trait Type<'a>: 'static + Sized {
        type Reified: 'a;
    }

    trait MaybeSizedType<'a>: 'static + Sized {
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

pub trait RequestType<'a>: tags::Type<'a> {
    type Params: 'a;
    type Answer: 'a;
    type Result: 'a;
}

pub trait CallbackRequest<'a, T: RequestType<'a>> {
    fn satisfy_with<F: FnOnce(T::Params) -> T::Answer>(self, f: F) -> T::Result;
}

pub struct ClosureRequester<'a, T: RequestType<'a>, F> {
    params: T::Params,
    closure: F,
}
impl<'a, T: RequestType<'a>, F> ClosureRequester<'a, T, F> {
    pub fn new(params: T::Params, closure: F) -> Self {
        Self { params, closure }
    }
}
impl<'a, T, C> CallbackRequest<'a, T> for ClosureRequester<'a, T, C>
where
    T: RequestType<'a>,
    C: FnOnce(T::Answer) -> T::Result,
{
    fn satisfy_with<F: FnOnce(T::Params) -> T::Answer>(self, f: F) -> T::Result {
        let answer = f(self.params);
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
pub(crate) struct TaggedOption<'a, T: tags::Type<'a>>(Option<T::Reified>);
impl<'a, T: tags::Type<'a>> Erased<'a> for TaggedOption<'a, T> {
    fn tag_id(&self) -> TypeId {
        TypeId::of::<T>()
    }
}
impl<'a, T: tags::Type<'a>> TaggedOption<'a, T> {
    unsafe fn as_demand(&mut self) -> &mut Demand<'a> {
        std::mem::transmute(self as &mut dyn Erased)
    }
    pub(crate) unsafe fn as_request(&mut self) -> &mut Request<'a> {
        std::mem::transmute(self as &mut dyn Erased)
    }
    fn take(&mut self) -> Option<T::Reified> {
        self.0.take()
    }
}

#[repr(transparent)]
struct Demand<'a>(dyn Erased<'a> + 'a);
impl<'a> Demand<'a> {
    fn provide<T: tags::Type<'a>>(&mut self, value: T::Reified) -> &mut Self {
        if let Some(res @ TaggedOption(None)) = self.0.downcast_mut::<T>() {
            res.0 = Some(value)
        }
        self
    }
    fn provide_with<T: tags::Type<'a>>(&mut self, f: impl FnOnce() -> T::Reified) -> &mut Self {
        if let Some(res @ TaggedOption(None)) = self.0.downcast_mut::<T>() {
            res.0 = Some(f())
        }
        self
    }

    pub fn provide_ref<T: tags::Type<'a>>(&mut self, value: &'a T::Reified) -> &mut Self {
        self.provide::<tags::Ref<tags::MaybeSizedValue<T>>>(value)
    }
    pub fn provide_value<T: tags::Type<'a>>(
        &mut self,
        f: impl FnOnce() -> T::Reified,
    ) -> &mut Self {
        self.provide_with::<tags::Value<T>>(f)
    }
}

pub(crate) type RequestTag<'a, T> = tags::RefMut<tags::MaybeSizedValue<dyn CallbackRequest<'a, T>>>;

#[repr(transparent)]
/// A type-erased callback request for some potentially context-specific values.
///
/// Since the actual type of the request is erased callbacks must first specify a type when
/// wanting to satisfy the request. This is done with the type parameter `T` on the
/// [`satisfy_with`] method.
pub struct Request<'a>(dyn Erased<'a>);
impl<'a> Request<'a> {
    /// Satisfy the given Request type `T` using the provided closure.
    ///
    /// If the type of the request is not `T` or if the request was already satisfied this method
    /// returns `None`.
    pub fn satisfy_with<T: RequestType<'a>>(
        &mut self,
        f: impl FnOnce(T::Params) -> T::Answer,
    ) -> Option<T::Result> {
        if let Some(mech) = self
            .0
            .downcast_mut::<RequestTag<'a, T>>()
            .and_then(TaggedOption::take)
        {
            Some(mech.satisfy_with(f))
        } else {
            None
        }
    }
}

pub(crate) fn req<'a, T: RequestType<'a>>(
    mechcb: &'a mut dyn CallbackRequest<'a, T>,
) -> TaggedOption<'a, RequestTag<'a, T>> {
    TaggedOption::<'a, RequestTag<'a, T>>(Some(mechcb));
}

trait ValidationProvider<'a> {
    fn provide(&'a self, req: &mut Demand<'a>);
}

#[repr(transparent)]
pub struct Validate<'a>(dyn ValidationProvider<'a>);
impl<'a> Validate<'a> {
    fn provide_by_tag<T: tags::Type<'a>>(&self) -> Option<T::Reified> {
        let mut tagged_option = TaggedOption::<'a, T>(None);
        self.0.provide(unsafe { tagged_option.as_demand() });
        tagged_option.0
    }
    pub fn provide_ref<T: tags::Type<'a>>(&self) -> Option<&T::Reified> {
        self.provide_by_tag::<tags::Ref<tags::MaybeSizedValue<T>>>()
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
    /// TODO: UPDATE!
    /// ```rust
    /// # use std::sync::Arc;
    /// # use rsasl::callback::Callback;
    /// # use rsasl::error::SessionError;
    /// # use rsasl::error::SessionError::NoCallback;
    /// # use rsasl::Property;
    /// use rsasl::property::{properties, Password, CallbackQ};
    /// # use rsasl::session::SessionData;
    /// # struct CB;
    /// # impl Callback for CB {
    /// fn callback(&self, session: &mut SessionData, query: &dyn CallbackQ) -> Result<(), SessionError> {
    ///     let property = query.property();
    ///     match property {
    ///         properties::PASSWORD => {
    ///             session.set_property::<Password>(Arc::new("secret".to_string()));
    ///             Ok(())
    ///         }
    ///         _ => {
    ///             Err(NoCallback { property })
    ///         }
    ///     }
    /// }
    /// # }
    /// ```
    ///
    /// In some cases (e.g. [`OpenID20AuthenticateInBrowser`] the mechanism expects that a certain
    /// action is taken by the user instead of an explicit property being provided (e.g. to
    /// authenticate to their OIDC IdP using the system's web browser).
    fn callback<'a>(
        &self,
        session_data: &SessionData,
        request: &mut Request<'a>,
    ) -> Result<(), CallbackError> {
        Err(CallbackError::NoCallback)
    }

    /// Validate an authentication exchange
    ///
    /// This callback will only be issued on the server side of an authentication exchange to
    /// validate the data passed in by the client side. Some mechanisms do not use this validation
    /// system at all and instead only issue calls to [`provide_prop`], e.g. the (S)CRAM and DIGEST
    /// family of mechanisms. Check the documentation of the mechanisms you need to support for
    /// details on how to authenticate users server side.
    ///
    /// If used the `validation` parameter defines the exact validation to be performed. Most
    /// mechanisms in this crate define their own validation system, with the exception of
    /// `PLAIN` and `LOGIN` which both use [`SIMPLE`] (username / password) as validation.
    ///
    /// See the [`validate module documentation`](crate::validate) for details on how to
    /// implement each validation.
    fn validate<'a>(
        &self,
        _session_data: &SessionData,
        _query: &Validate<'a>,
    ) -> Result<(), ValidationError> {
        Err(ValidationError::NoValidation)
    }
}

#[test]
fn cb_test() {
    #[derive(Debug)]
    struct Q {
        p: u64,
    };
    impl Answerable for Q {
        type Answer = u64;

        fn respond(&mut self, resp: Self::Answer) {
            self.p = resp;
        }

        fn into_answer(self) -> Option<Self::Answer> {
            Some(self.p)
        }
    }
    struct CB;
    impl SessionCallback for CB {
        fn callback(&self, _s: &SessionData, query: &mut dyn Query) -> Result<(), CallbackError> {
            if let Some(q) = Q::downcast_mut(query) {
                Ok(q.respond(42))
            } else {
                Err(CallbackError::NoCallback)
            }
        }
    }
    let cb = CB;
    let mut md = MechanismData::new(Arc::new(cb), None, PLAIN.clone(), Side::Client);
    let mut q = Q { p: 0 };
    let o = md.callback::<Q>(&mut q);
    println!("{:?}: {:?}", o, q);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mechanisms::plain::server::PlainValidation;
    use std::ptr::NonNull;

    #[test]
    fn test_validateq() {
        struct CB;
        impl Callback for CB {
            fn validate(
                &self,
                session: &mut SessionData,
                query: &dyn ValidateQ,
            ) -> Result<(), SessionError> {
                if let Some(p) = PlainValidation::downcast(query) {
                    println!("YAY! {:?}", p);
                } else if let Some(p) = PlainValidation::downcast(query) {
                    println!("BOOP!");
                }

                Ok(())
            }
        }

        let vquery = PlainValidation {
            authzid: Some("zid".into()),
            authcid: "cid".into(),
            password: "pass".into(),
        };
        let sd = unsafe { NonNull::dangling().as_mut() };
        let r = CB.validate(sd, &vquery);
        println!("{:?}", r);
    }
}
