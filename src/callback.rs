use std::any::Any;
use std::fmt::Debug;
use crate::consts::{AUTHID, CallbackAction, Gsasl_property, Property};
use crate::{Mechname, SASLError};
use crate::SASLError::{NoCallback, NoValidate};
use crate::session::SessionData;
use crate::validate::Validation;

pub trait Callback {
    fn provide_prop(&self, _session: &mut SessionData, action: CallbackAction)
        -> Result<(), SASLError>
    {
        let code = action.code();
        return Err(NoCallback { code })
    }

    fn validate(&self, session: &mut SessionData, validation: &'static dyn Validation)
        -> Result<(), SASLError>
    {
        return Err(NoValidate { validation })
    }
}
