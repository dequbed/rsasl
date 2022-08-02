use crate::context::EmptyProvider;
use crate::mechanism::Authentication;
use crate::property::AuthId;
use crate::session::{MechanismData, State};
use std::io::Write;
use crate::error::SessionError;

#[derive(Copy, Clone, Debug)]
pub struct External;

impl Authentication for External {
    fn step(
        &mut self,
        session: &mut MechanismData,
        _input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<(State, Option<usize>), SessionError> {
        let mut len = None;

        session.need_with::<AuthId, _, ()>(&EmptyProvider, |authid| {
            let buf = authid.as_bytes();
            writer.write_all(buf)?;
            len = Some(buf.len());
            Ok(())
        })?;

        Ok((State::Finished, len))
    }
}
