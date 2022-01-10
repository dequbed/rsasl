use crate::SASLError;
use crate::property::Property;
use crate::SASLError::{NoCallback, NoValidate};
use crate::session::SessionData;
use crate::validate::Validation;

pub trait Callback {
    fn provide_prop(&self, _session: &mut SessionData, property: Property)
        -> Result<(), SASLError>
    {
        return Err(NoCallback { property })
    }

    fn validate(&self, _session: &mut SessionData, validation: &'static dyn Validation)
        -> Result<(), SASLError>
    {
        return Err(NoValidate { validation })
    }
}
