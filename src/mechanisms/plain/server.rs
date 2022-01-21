use std::io::Write;
use std::sync::Arc;
use stringprep::saslprep;
use crate::property::{AuthId, AuthzId, Password};
use crate::session::{SessionData, StepResult};
use crate::{Authentication, SASLError};
use crate::session::Step::{Done, NeedsMore};
use crate::validate::validations::SIMPLE;

pub struct Plain;
impl Authentication for Plain {
    fn step(&mut self, session: &mut SessionData, input: Option<&[u8]>, _writer: &mut dyn Write)
        -> StepResult
    {
        if input.map(|buf| buf.len()).unwrap_or(0) == 0 {
            return Ok(NeedsMore(None));
        }

        let input = input.unwrap();
        let mut split = input.split(|byte| *byte == 0);
        let authzid: &[u8] = split.next().ok_or(SASLError::MechanismParseError)?;
        let authcid: &[u8] = split.next().ok_or(SASLError::MechanismParseError)?;
        let password: &[u8] = split.next().ok_or(SASLError::MechanismParseError)?;
        if split.next().is_some() {
            return Err(SASLError::MechanismParseError);
        }

        if !authzid.is_empty() {
            let s = std::str::from_utf8(authzid)
                .map_err(|_| SASLError::MechanismParseError)?;
            let authzidprep = saslprep(s)?.to_string();
            session.set_property::<AuthzId>(Arc::new(authzidprep));
        }

        let authcid = std::str::from_utf8(authcid)
            .map_err(|_| SASLError::MechanismParseError)?;
        let authcidprep = saslprep(authcid)?.to_string();
        session.set_property::<AuthId>(Arc::new(authcidprep));

        let password = std::str::from_utf8(password)
            .map_err(|_| SASLError::MechanismParseError)?;
        let passwordprep = saslprep(password)?.to_string();
        session.set_property::<Password>(Arc::new(passwordprep));

        session.validate(SIMPLE)?;
        Ok(Done(None))
    }
}