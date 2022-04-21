use crate::mechanism::Authentication;
use crate::property::AuthId;
use crate::session::Step::Done;
use crate::session::{MechanismData, StepResult};
use std::io::Write;

#[derive(Copy, Clone, Debug)]
pub struct External;

impl Authentication for External {
    fn step(
        &mut self,
        session: &mut MechanismData,
        _input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> StepResult {
        if let Some(authid) = session.get_property_or_callback::<AuthId>()? {
            let buf = authid.as_bytes();
            writer.write_all(buf)?;
            Ok(Done(Some(buf.len())))
        } else {
            Ok(Done(None))
        }
    }
}
