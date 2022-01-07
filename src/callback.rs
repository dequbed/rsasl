use std::any::Any;
use std::fmt::Debug;
use crate::consts::{AuthId, AuthzId, GetProperty, Gsasl_property, SetProperty};
use crate::{eq_type, Mechname, SASL, SASLError};
use crate::SASLError::{NoCallback, NoCallbackDyn, NoValidate};
use crate::session::SessionData;
use crate::validate::Validation;

pub trait Callback {
    fn provide_prop(&self, _session: &mut SessionData, property: &'static dyn GetProperty)
        -> Result<(), SASLError>
    {
        return Err(NoCallbackDyn { property })
    }

    fn validate(&self, _session: &mut SessionData, validation: &'static dyn Validation)
        -> Result<(), SASLError>
    {
        return Err(NoValidate { validation })
    }
}
