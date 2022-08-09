use crate::context::EmptyProvider;
use crate::error::SessionError;
use crate::mechanism::Authentication;
use crate::session::{MechanismData, State};
use std::io::Write;
use super::AnonymousToken;

#[derive(Copy, Clone, Debug)]
pub struct Anonymous;
impl Authentication for Anonymous {
    fn step(
        &mut self,
        session: &mut MechanismData,
        _input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<(State, Option<usize>), SessionError> {
        let len = session.maybe_need_with::<AnonymousToken, _, _>(&EmptyProvider, |token| {
            writer.write_all(token.as_bytes())?;
            Ok(token.len())
        })?.unwrap_or(0);
        Ok((State::Finished, Some(len)))
    }
}
