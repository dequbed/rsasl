use std::io::Write;
use crate::mechanism::Authentication;
use crate::property::AnonymousToken;
use crate::{Mechanism, Mechname, SASLError};
use crate::session::{SessionData, StepResult};
use crate::session::Step::Done;

#[derive(Copy, Clone, Debug)]
pub struct Anonymous;

impl Authentication for Anonymous {
    fn step(&mut self, session: &mut SessionData, _input: Option<&[u8]>, writer: &mut dyn Write)
        -> StepResult
    {
        if let Ok(token) = session.get_property_or_callback::<AnonymousToken>() {
            let buf = token.as_bytes();
            writer.write_all(buf)?;
            Ok(Done(Some(buf.len())))
        } else {
            Err(SASLError::no_property::<AnonymousToken>())
        }
    }
}

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS_CLIENT};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS_CLIENT))]
pub static ANONYMOUS_CLIENT: Mechanism = Mechanism {
    mechanisms: &[Mechname::const_new_unchecked("ANONYMOUS")],
    matches: |name| name.as_str() == "ANONYMOUS",
    start: |_sasl| Ok(Box::new(Anonymous)),
};