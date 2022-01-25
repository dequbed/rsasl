use std::fmt::{Display, Formatter};
use std::io::Write;
use std::sync::Arc;
use crate::error::{MechanismError, MechanismErrorKind};
use crate::mechanism::Authentication;
use crate::property::AuthId;
use crate::session::{SessionData, StepResult};
use crate::validate::validations::EXTERNAL;
use crate::session::Step::Done;

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

#[derive(Copy, Clone, Debug)]
pub struct External;

impl Authentication for External {
    fn step(&mut self, session: &mut SessionData, input: Option<&[u8]>, _writer: &mut dyn Write)
        -> StepResult
    {
        if let Some(input) = input {
            if let Ok(authid) = std::str::from_utf8(input) {
                session.set_property::<AuthId>(Arc::new(authid.to_string()));
            } else {
                return Err(ParseError.into());
            }
        }

        session.validate(EXTERNAL)?;
        Ok(Done(None))
    }
}