use crate::mechanism::Authentication;
use crate::property::AuthId;
use crate::session::{MechanismData, State, StepResult};
use std::io::Write;
use crate::context::EmptyProvider;

#[derive(Copy, Clone, Debug)]
pub struct External;

impl Authentication for External {
    fn step(
        &mut self,
        session: &mut MechanismData,
        _input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> StepResult {
        let mut len = None;

        session.need_with::<AuthId, _, ()>(&EmptyProvider, &mut |authid| {
            let buf = authid.as_bytes();
            writer.write_all(buf)?;
            len = Some(buf.len());
            Ok(())
        })?;

        Ok((State::Finished, len))
    }
}
