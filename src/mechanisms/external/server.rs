use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::mechanism::Authentication;
use thiserror::Error;

use crate::context::{EmptyProvider, ThisProvider};
use crate::property::AuthId;
use crate::session::{MechanismData, State};
use std::io::Write;

#[derive(Debug, Eq, PartialEq, Copy, Clone, Error)]
#[error("the given external token is invalid UTF-8")]
pub struct ParseError;
impl MechanismError for ParseError {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}

#[derive(Copy, Clone, Debug)]
pub struct External;

impl Authentication for External {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        _writer: &mut dyn Write,
    ) -> Result<(State, Option<usize>), SessionError> {
        if let Some(input) = input {
            if let Ok(authid) = std::str::from_utf8(input) {
                let provider = ThisProvider::<AuthId>::with(authid);
                session.validate(&provider)?;
            } else {
                return Err(ParseError.into());
            }
        } else {
            session.validate(&EmptyProvider)?;
        }

        Ok((State::Finished, None))
    }
}
