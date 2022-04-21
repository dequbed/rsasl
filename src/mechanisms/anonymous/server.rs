use crate::error::{MechanismError, MechanismErrorKind};
use crate::property::AnonymousToken;
use crate::session::Step::{Done, NeedsMore};
use crate::session::{MechanismData, StepResult};
use crate::validate::validations::ANONYMOUS;
use crate::Authentication;
use std::fmt::{Display, Formatter};
use std::io::Write;
use std::sync::Arc;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct ParseError;
impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("the given anonymous token is invalid UTF-8 or longer than 255 chars")
    }
}
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
            return Ok(NeedsMore(None));
        };

        if let Ok(input) = std::str::from_utf8(input) {
            /* token       = 1*255TCHAR
            The <token> production is restricted to 255 UTF-8 encoded Unicode
            characters.   As the encoding of a characters uses a sequence of 1
            to 4 octets, a token may be long as 1020 octets. */
            if input.len() == 0 || input.len() > 255 {
                return Err(ParseError.into());
            }

            session.set_property::<AnonymousToken>(Arc::new(input.to_string()));
            session.validate(&ANONYMOUS)?;

            Ok(Done(None))
        } else {
            Err(ParseError.into())
        }
    }
}
