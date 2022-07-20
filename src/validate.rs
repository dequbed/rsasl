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
//! # use std::sync::Arc;
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
//! # const MECHS: &[&'static Mechname] = &[];
//! fn do_auth(config: Arc<ServerConfig>) {
//!     let sasl = SASLServer::<MyValidation>::new(config);
//!
//!     let mut session = sasl.start_suggested(MECHS.iter()).unwrap();
//!     // do authenthentication stepping and so on
//!
//!     // Since `SASLServer` was constructed with `MyValidation`, calling `validation()` returns
//!     // `Option<MyDataType>`
//!     let my_data_type: MyDataType = session.validation().expect("user callback didn't validate");
//! }
//! ```

use crate::typed::{tags, Erased, TaggedOption};
use std::any::TypeId;
use thiserror::Error;

pub trait Validation: 'static {
    type Value: 'static;
}
impl<'a, V: Validation> tags::Type<'a> for V {
    type Reified = V::Value;
}

#[derive(Debug)]
/// A default "Validation" that expects no data to be set.
///
/// You will rarely use this type explicitly as it's rather useless.
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
impl Validate<'_> {
    pub(crate) fn new<'opt, V: Validation>(opt: &'opt mut TaggedOption<'_, V>) -> &'opt mut Self {
        unsafe { std::mem::transmute(opt as &mut dyn Erased) }
    }
}
impl<'a> Validate<'a> {
    #[inline(always)]
    pub fn is<T: Validation>(&self) -> bool {
        self.0.tag_id() == TypeId::of::<T>()
    }

    /// Finalize the authentication exchange by providing a last value to the mechanism
    ///
    /// The requested value of a [`Validation`] depends on the protocol implementation. It's
    /// usually designed to extract relevant information out of the authentication exchange.
    pub fn finalize<T: Validation>(&mut self, outcome: T::Value) -> Result<&mut Self, ()> {
        if let Some(result @ TaggedOption(Option::None)) = self.0.downcast_mut::<T>() {
            *result = TaggedOption(Some(outcome));
            Err(())
        } else {
            Ok(self)
        }
    }

    pub fn with<T, F, E>(&mut self, f: F) -> Result<&mut Self, ValidationError>
    where
        T: Validation,
        F: FnOnce() -> Result<T::Value, E>,
        E: std::error::Error + Send + Sync + 'static,
    {
        if let Some(result @ TaggedOption(Option::None)) = self.0.downcast_mut::<T>() {
            match f() {
                Ok(outcome) => {
                    *result = TaggedOption(Some(outcome));
                    Ok(self)
                }
                Err(error) => Err(ValidationError::Boxed(Box::new(error).into())),
            }
        } else {
            Ok(self)
        }
    }
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error(transparent)]
    Boxed(Box<dyn std::error::Error + Send + Sync>),
}