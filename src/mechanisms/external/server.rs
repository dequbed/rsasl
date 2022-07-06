use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::mechanism::Authentication;
use thiserror::Error;

use crate::mechanisms::external::client::AuthId;
use crate::session::Step::Done;
use crate::session::{MechanismData, StepResult};
use std::io::Write;
use crate::context::ThisProvider;
use crate::property::Property;

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

impl Property for ExternalValidation {
    type Value = bool;
}
impl Validation for ExternalValidation {}

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
