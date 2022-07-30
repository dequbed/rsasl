use crate::context::EmptyProvider;
use crate::mechanism::Authentication;
use crate::property::Property;
use crate::session::{MechanismData, State};
use std::io::Write;
use crate::error::SessionError;

pub struct AnonymousToken;
impl Property for AnonymousToken {
    type Value = str;
}

#[derive(Copy, Clone, Debug)]
pub struct Anonymous;
impl Authentication for Anonymous {
    fn step(
        &mut self,
        session: &mut MechanismData,
        _input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<(State, Option<usize>), SessionError> {
        let mut len = None;
        session.need_with::<AnonymousToken, _, ()>(&EmptyProvider, &mut |token| {
            let buf = token.as_bytes();
            writer.write_all(buf)?;
            len = Some(buf.len());
            Ok(())
        })?;
        Ok((State::Finished, len))
    }
}
