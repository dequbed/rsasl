use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::mechanism::Authentication;

use crate::session::Step::Done;
use crate::session::{MechanismData, StepResult};
use std::fmt::{Display, Formatter};
use std::io::Write;
use crate::callback::tags::Type;
use crate::callback::ThisProvider;

use crate::validate::Validation;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct ParseError;
impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("the given external token is invalid UTF-8")
    }
}
impl MechanismError for ParseError {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}

pub struct ExternalValidation;

impl<'a> Type<'a> for ExternalValidation { type Reified = bool; }
impl<'a> Validation<'a> for ExternalValidation {}

#[derive(Copy, Clone, Debug)]
pub struct External;

impl Authentication for External {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        _writer: &mut dyn Write,
    ) -> StepResult {
        let outcome = if let Some(input) = input {
            if let Ok(authid) = std::str::from_utf8(input) {
                let provider = ThisProvider(authid);
                session.validate::<ExternalValidation, _>(&provider)
            } else {
                return Err(ParseError.into());
            }
        } else {
            session.validate::<ExternalValidation, _>(&())
        }?;

        if outcome {
            Ok(Done(None))
        } else {
            Err(SessionError::AuthenticationFailure)
        }
    }
}
