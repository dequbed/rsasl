use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::mechanism::Authentication;
use thiserror::Error;

use crate::callback::tags::Type;
use crate::callback::ThisProvider;
use crate::mechanisms::external::client::AuthId;
use crate::session::Step::Done;
use crate::session::{MechanismData, StepResult};
use std::fmt::{Display, Formatter};
use std::io::Write;

use crate::validate::Validation;

#[derive(Debug, Eq, PartialEq, Copy, Clone, Error)]
#[error("the given external token is invalid UTF-8")]
pub struct ParseError;
impl MechanismError for ParseError {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}

pub struct ExternalValidation;

impl<'a> Type<'a> for ExternalValidation {
    type Reified = bool;
}
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
                let provider = ThisProvider::<AuthId>::with(authid);
                session.validate::<ExternalValidation, _>(&provider)
            } else {
                return Err(ParseError.into());
            }
        } else {
            session.validate::<ExternalValidation, _>(&())
        };

        let outcome = outcome.map_err(|_| ParseError /* FIXME!! */)?;

        if outcome {
            Ok(Done(None))
        } else {
            Err(SessionError::AuthenticationFailure)
        }
    }
}
