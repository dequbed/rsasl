use std::io::Write;
use crate::{Mechanism, Mechname};
use crate::mechanism::Authentication;
use crate::property::AuthId;
use crate::session::{SessionData, StepResult};
use crate::session::Step::Done;

#[derive(Copy, Clone, Debug)]
pub struct External;

impl Authentication for External {
    fn step(&mut self, session: &mut SessionData, _input: Option<&[u8]>, writer: &mut dyn Write)
        -> StepResult
    {
        if let Ok(authid) = session.get_property_or_callback::<AuthId>() {
            let buf = authid.as_bytes();
            writer.write_all(buf)?;
            Ok(Done(Some(buf.len())))
        } else {
            Ok(Done(None))
        }
    }
}

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS_CLIENT};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS_CLIENT))]
pub static EXTERNAL_CLIENT: Mechanism = Mechanism {
    mechanisms: &[Mechname::const_new_unchecked("EXTERNAL")],
    matches: |name| name.as_str() == "EXTERNAL",
    start: |_sasl| Ok(Box::new(External)),
};
