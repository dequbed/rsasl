use std::io::Write;
use crate::{Authentication, SASLError};
use crate::property::AnonymousToken;
use crate::session::{SessionData, StepResult};
use crate::session::Step::{Done, NeedsMore};
use crate::validate::ANONYMOUS;

#[derive(Copy, Clone, Debug)]
pub struct Anonymous;

impl Authentication for Anonymous {
    fn step(&mut self, session: &mut SessionData, input: Option<&[u8]>, _writer: &mut dyn Write)
        -> StepResult
    {
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
                return Err(SASLError::MechanismParseError);
            }

            session.set_property::<AnonymousToken>(Box::new(input.to_string()));
            session.validate(ANONYMOUS)?;

            Ok(Done(None))
        } else {
            Err(SASLError::MechanismParseError)
        }
    }
}
