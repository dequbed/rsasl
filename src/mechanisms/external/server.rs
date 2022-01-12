use std::io::Write;
use crate::{Mechanism, Mechname};
use crate::mechanism::Authentication;
use crate::property::AuthId;
use crate::session::{SessionData, StepResult};
use crate::validate::EXTERNAL;
use crate::session::Step::Done;
use crate::SASLError::MechanismParseError;

#[derive(Copy, Clone, Debug)]
pub struct External;

impl Authentication for External {
    fn step(&mut self, session: &mut SessionData, input: Option<&[u8]>, writer: &mut dyn Write)
        -> StepResult
    {
        if let Some(input) = input {
            if let Ok(authid) = std::str::from_utf8(input) {
                session.set_property::<AuthId>(Box::new(authid.to_string()));
            } else {
                return Err(MechanismParseError);
            }
        }

        session.validate(EXTERNAL)?;
        Ok(Done(None))
    }
}

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS_CLIENT};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS_CLIENT))]
pub static EXTERNAL_SERVER: Mechanism = Mechanism {
    mechanisms: &[Mechname::const_new_unchecked("EXTERNAL")],
    matches: |name| name.as_str() == "EXTERNAL",
    start: |_sasl| Ok(Box::new(External)),
};
