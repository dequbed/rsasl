//! User-provided callbacks
//!
//! Make very generic data go from user to mechanism and vice versa through the protocol impl
//! that should not need to care about the shape of this data.
//! Yeah, *all* the runtime reflection.
//!
//! ## Why not just return the requested value from a callback?
//! Because that would devolve to basically `fn callback(query: Box<dyn Any>) -> Box<dyn Any>`
//! with exactly zero protection against accidentally not providing some required data.


use std::error::Error;
use std::fmt::{Display, Formatter};



use crate::session::SessionData;



mod sealed {
    use std::any::Any;

    pub trait Sealed {
        fn as_any_mut(&mut self) -> &mut dyn Any;
        fn as_any(&self) -> &dyn Any;
    }
    impl<T: Any> Sealed for T {
        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }
}

/// Really just `dyn Any` with a sprinkle of syntactic sugar.
pub trait Query: 'static + sealed::Sealed {
    #[inline(always)]
    fn downcast_mut(d: &mut dyn Query) -> Option<&mut Self> where Self: Sized {
        d.as_any_mut().downcast_mut::<Self>()
    }
    #[inline(always)]
    fn downcast(d: &dyn Query) -> Option<&Self> where Self: Sized {
        d.as_any().downcast_ref::<Self>()
    }
}
impl<T: 'static> Query for T {}

/// Query type that expects an answer
pub trait Answerable: Query {
    type Answer;

    // callbacks in callbacks yay
    fn respond(&mut self, resp: Self::Answer);
    fn into_answer(self) -> Option<Self::Answer>;
}
pub trait Question {
    type Params;
    fn build(params: Self::Params) -> Self;
}
pub trait AnsQuery: Question + Answerable {}
impl<T: Question + Answerable> AnsQuery for T {}

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
    fn callback(&self, _session_data: &SessionData, _query: &mut dyn Query)
        -> Result<(), CallbackError>
    {
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
    fn validate(&self, _session_data: &SessionData, _query: &dyn Query)
        -> Result<(), ValidationError>
    {
        Err(ValidationError::NoValidation)
    }
}

#[test]
fn cb_test() {
    #[derive(Debug)]
    struct Q { p: u64 };
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
        fn callback(&self, _s: &SessionData, query: &mut dyn Query) -> Result<(),
            CallbackError> {
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
    use std::ptr::NonNull;
    use crate::mechanisms::plain::server::PlainValidation;
    use super::*;

    #[test]
    fn test_validateq() {
        struct CB;
        impl Callback for CB {
            fn validate(&self, session: &mut SessionData, query: &dyn ValidateQ) -> Result<(), SessionError> {
                if let Some(p) = PlainValidation::downcast(query) {
                    println!("YAY! {:?}", p);
                } else if let Some(p) = PlainValidation::downcast(query) {
                    println!("BOOP!");
                }

                Ok(())
            }
        }

        let vquery = PlainValidation { authzid: Some("zid".into()), authcid: "cid".into(), password: "pass".into() };
        let sd = unsafe { NonNull::dangling().as_mut() };
        let r = CB.validate(sd, &vquery);
        println!("{:?}", r);
    }
}