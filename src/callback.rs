use std::any::Any;
use std::fmt::Debug;
use crate::consts::{AUTHID, Gsasl_property, Property};
use crate::SASLError;
use crate::SASLError::NoCallback;
use crate::session::SessionData;

pub trait Callback {
    // Old Style
    fn callback(&self, session: &mut SessionData, code: Gsasl_property) -> Result<(), SASLError>;

    // New Style
    /// Provide the requested property to `session` by calling [`SessionData::set_property()`]
    fn provide_property<P: Property>(&self, session: &mut SessionData)
        -> Result<(), SASLError>
    where Self: Sized {
        let code = P::code();
        return Err(NoCallback { code })
    }

    fn provide_property_dyn(&self, session: &mut SessionData, property: &dyn Property<Item=&dyn Any>)
        -> Result<(), SASLError>
    {
        let code = AUTHID::code();
        return Err(NoCallback { code })
    }
}
