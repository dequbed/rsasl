use crate::error::{MechanismError, MechanismErrorKind};
use crate::mechanism::Authentication;
use crate::property::AuthId;
use crate::session::Step::Done;
use crate::session::{MechanismData, StepResult};
use crate::validate::validations::EXTERNAL;
use std::fmt::{Display, Formatter};
use std::io::Write;
use std::sync::Arc;
use crate::validate::{Validation, ValidationQ};

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
impl ValidationQ for ExternalValidation {
    fn validation() -> Validation where Self: Sized {
        EXTERNAL
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
    ) -> StepResult {
        if let Some(input) = input {
            if let Ok(authid) = std::str::from_utf8(input) {
                session.set_property::<AuthId>(Arc::new(authid.to_string()));
            } else {
                return Err(ParseError.into());
            }
        }

        session.validate(&ExternalValidation)?;
        Ok(Done(None))
    }
}
