use std::any::TypeId;
use std::marker::PhantomData;
use crate::callback::{RequestResponse, TOKEN};
use crate::property::Property;
use crate::typed::{Erased, TaggedOption, tags};

enum ValidationOutcome {
    Successful,
    Failed,
}

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

    pub fn finalize<T: Validation>(&mut self, outcome: T::Value) -> RequestResponse<&mut Self> {
        if let Some(result @ TaggedOption(Option::None)) = self.0.downcast_mut::<T>() {
            *result = TaggedOption(Some(outcome));
            RequestResponse::Break(TOKEN(PhantomData))
        } else {
            RequestResponse::Continue(self)
        }
    }
}

#[derive(Debug)]
pub enum ValidationError {
    NoValidation,
    BadAuthentication,
    BadAuthorization,
}