use core::str::Utf8Error;
use crate::context::ThisProvider;
use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::mechanism::Authentication;
use crate::session::{MechanismData, State};
use super::AnonymousToken;
use std::io::Write;
use thiserror::Error;

#[derive(Debug, Eq, PartialEq, Copy, Clone, Error)]
#[error("anonymous token received is invalid UTF-8 or longer than 255 chars")]
pub struct ParseError(Utf8Error);
impl MechanismError for ParseError {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Anonymous;
impl Authentication for Anonymous {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        _writer: &mut dyn Write,
    ) -> Result<(State, Option<usize>), SessionError> {
        // Treat an input of `None` like an empty slice. This is a gray zone in behaviour but can
        // not lead to loops since this mechanism will *always* return State::Finished.
        let input = core::str::from_utf8(input.unwrap_or(&[]))
            .map_err(ParseError)?;
        // The input is not further validated and passed to the user as-is.
        session.validate(&ThisProvider::<AnonymousToken>::with(input))?;
        Ok((State::Finished, None))
    }
}