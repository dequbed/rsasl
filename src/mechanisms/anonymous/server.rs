use crate::context::ThisProvider;
use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::session::{MechanismData, State, StepResult};
use crate::mechanism::Authentication;
use crate::mechanisms::anonymous::client::AnonymousToken;
use std::io::Write;
use thiserror::Error;

#[derive(Debug, Eq, PartialEq, Copy, Clone, Error)]
#[error("anonymous token received is invalid UTF-8 or longer than 255 chars")]
pub struct ParseError;
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
    ) -> StepResult {
        let input = if let Some(buf) = input {
            buf
        } else {
            return Err(SessionError::InputDataRequired);
        };

        if let Ok(input) = std::str::from_utf8(input) {
            /* token       = 1*255TCHAR
            The <token> production is restricted to 255 UTF-8 encoded Unicode
            characters.   As the encoding of a characters uses a sequence of 1
            to 4 octets, a token may be long as 1020 octets. */
            if input.len() == 0 || input.chars().count() > 255 {
                return Err(ParseError.into());
            }

            session.validate(&ThisProvider::<AnonymousToken>::with(input))?;
            Ok((State::Finished, None))
        } else {
            Err(ParseError.into())
        }
    }
}
