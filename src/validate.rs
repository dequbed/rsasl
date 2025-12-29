//! Extracting information from authentication exchanges
//!
//! For the server side of an authentication it is usually required to be able to extract some
//! meaningful information from the authentication, e.g. the user that was just authenticated.
//!
//! [`Validation`] provide a facility to enable exactly that, by enabling the user-provided
//! callback to send data to the protocol implementation (i.e. the code calling `Session::step`
//! or `step64`) while having access to the entire context of the authentication exchange.
//!
//! The type of this data can be freely selected by the protocol implementation.
//!
//! To do so a protocol implementation needs to implement the `Validation` trait on a marker type
//! and binds it on the `SASLServer` used. This marker type and the associated Value must both be
//! visible to the user providing the callback.
//!
//! ```
//! # #[cfg(all(not(miri), feature = "provider"))]
//! # {
//! # use std::convert::Infallible;
//! use std::sync::Arc;
//! use rsasl::prelude::*;
//! use rsasl::validate::Validation;
//!
//! pub struct MyDataType {
//!     pub username: String,
//!     pub authzid: Option<String>
//! }
//!
//! pub struct MyValidation;
//! impl Validation for MyValidation {
//!     // The Value can be any type that's `Sized` and `'static`.
//!     type Value = MyDataType;
//! }
//!
//! fn do_auth(config: Arc<SASLConfig>, selected: &Mechname) {
//!     let sasl = SASLServer::<MyValidation>::new(config);
//!
//!     let mut session = sasl.start_suggested(selected).unwrap();
//!     // do authentication stepping and so on
//!
//!     // Since `SASLServer` was constructed with `MyValidation`, calling `validation()` returns
//!     // `Option<MyDataType>`
//!     let my_data_type: MyDataType = session.validation().expect("user callback didn't validate");
//! }
//! # }
//! ```

use crate::alloc::boxed::Box;
use crate::typed::{tags, Erased, Tagged};
use core::any::TypeId;
use thiserror::Error;

/// Marker trait to define the type returned by `validation`
///
/// This trait is usually implemented on some zero-sized type (ZST):
/// ```rust
/// # use rsasl::prelude::Validation;
/// pub struct MyCustomValidation;
/// impl Validation for MyCustomValidation {
///     type Value = u32;
/// }
/// ```
///
/// However, it can also be implemented on any other type, which is useful if said type is the
/// one to be returned from the Validation:
/// ```rust
/// # use rsasl::prelude::Validation;
/// pub struct MyLoginUserType {
///     username: String,
/// }
/// impl Validation for MyLoginUserType {
///     type Value = Self;
/// }
/// ```
///
/// Often it is most useful to make `Value` a `Result` with the `Err` type changing the
/// authentication error that will be indicated to the client by the protocol implementation:
///
/// ```rust
/// # use rsasl::prelude::Validation;
/// pub struct MyCustomValidation;
/// pub struct Success { /* Fill with user data to be used on successful authentication */ }
/// pub enum Error {
///     // If this is returned from Validation, an "invalid credentials" type of error is returned
///     // (e.g. SMTP 535, XMPP 'not-authorized', …)
///     CredentialsInvalid,
///
///     // Return a "not permitted" type of error (e.g. SMTP 550, XMPP 'account-disabled' or
///     // 'credentials-expired'
///     LoginNotPermitted,
///
///     // Return a "temporary failure" type of error (e.g. SMTP 454, XMPP 'temporary-auth-failure')
///     TemporaryFailure {
///         reason: String,
///     }
///
///     // etc.
/// }
/// impl Validation for MyCustomValidation {
///     type Value = Result<Success, Error>;
/// }
/// ```
///
/// This way the user callback can implement all of the business logic of deciding on the error
/// type to be indicated to the client, making the protocol implementation more abstract and
/// reusable.
pub trait Validation: 'static {
    type Value: 'static;
}
impl<V: Validation> tags::Type<'_> for V {
    type Reified = Option<V::Value>;
}

#[derive(Debug)]
/// A default "Validation" that expects no data to be set.
///
/// You will rarely use this type explicitly as it's rather useless.
#[non_exhaustive]
pub struct NoValidation;
impl Validation for NoValidation {
    type Value = ();
}

#[repr(transparent)]
/// A type-erased validation request from a protocol crate
///
/// `Validate` behave very similar to the usual `Request`, but can only store 'Sized' values.
/// Additionally their data types are defined by the protocol implementation instead of the
/// mechanism.
pub struct Validate<'a>(dyn Erased<'a> + 'a);
#[cfg(any(test, feature = "provider", feature = "testutils"))]
impl<'a> Validate<'a> {
    pub(crate) fn new<'opt, V: Validation>(opt: &'opt mut Tagged<'a, V>) -> &'opt mut Self {
        unsafe { &mut *(opt as &mut dyn Erased as *mut dyn Erased as *mut Self) }
    }
}
impl Validate<'_> {
    #[inline(always)]
    pub fn is<T: Validation>(&self) -> bool {
        self.0.tag_id() == TypeId::of::<T>()
    }

    /// Finalize the authentication exchange by providing a last value to the mechanism
    ///
    /// The requested value of a [`Validation`] depends on the protocol implementation. It's
    /// usually designed to extract relevant information out of the authentication exchange.
    pub fn finalize<T: Validation>(&mut self, outcome: T::Value) {
        if let Some(result @ Tagged(Option::None)) = self.0.downcast_mut::<T>() {
            *result = Tagged(Some(outcome));
        }
    }

    pub fn with<T, F>(&mut self, f: F) -> Result<&mut Self, ValidationError>
    where
        T: Validation,
        F: FnOnce() -> Result<T::Value, ValidationError>,
    {
        if let Some(result @ Tagged(Option::None)) = self.0.downcast_mut::<T>() {
            let outcome = f()?;
            *result = Tagged(Some(outcome));
        }
        Ok(self)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ValidationError {
    #[error("A required property was not provided")]
    MissingRequiredProperty,
    #[error(transparent)]
    Boxed(Box<dyn std::error::Error + Send + Sync>),
}
