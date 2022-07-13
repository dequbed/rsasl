use crate::property::Property;
use crate::typed::{tags, Erased, TaggedOption};
use std::any::TypeId;
use std::marker::PhantomData;

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
    pub fn finalize<T: Validation>(&mut self, outcome: T::Value) -> Result<(), ()> {
        if let Some(result @ TaggedOption(Option::None)) = self.0.downcast_mut::<T>() {
            *result = TaggedOption(Some(outcome));
            Ok(())
        } else {
            Err(())
        }
    }
}

#[derive(Debug)]
pub enum ValidationError {
    NoValidation,
    BadAuthentication,
    BadAuthorization,
    #[doc(hidden)]
    EarlyReturn(PhantomData<()>),
}
