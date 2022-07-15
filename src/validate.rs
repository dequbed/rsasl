use crate::property::Property;
use crate::typed::{tags, Erased, TaggedOption};
use std::any::TypeId;
use thiserror::Error;

pub trait Validation: Property {}
impl<'a, V: Validation> tags::Type<'a> for V {
    type Reified = V::Value;
}

#[repr(transparent)]
pub struct Validate<'a>(dyn Erased<'a> + 'a);
impl<'a> Validate<'a> {
    pub(crate) fn new<'o, V: Validation>(opt: &'o mut TaggedOption<'a, V>) -> &'o mut Self {
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
    /// The final `outcome` value of a [`Validation`] depends on the specific mechanism that was
    /// used, but will usually be a `bool` or `Result` type.
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
    #[error("validation callback is not implemented for this validation type")]
    NoValidation,
    #[error(transparent)]
    Boxed(Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
// Validation really is for the protocol implementation. So it should if anything return a type
// *requested by the protocol implementation*, to allow more complex error types in the protocol
// (think HTTP 401 vs 403 [auth failed, auth successful but with invalid authzid])
pub enum ValidationOutcome {
    Successful,
    AuthenticationFailed,
    AuthorizationFailed,
}
