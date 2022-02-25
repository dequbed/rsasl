use std::fmt::{Display, Formatter};
use std::io::Write;
use std::str::Utf8Error;
use std::sync::Arc;

use stringprep::{saslprep, Error};

use crate::error::{MechanismError, MechanismErrorKind};
use crate::property::{AuthId, AuthzId, Password};
use crate::session::Step::{Done, NeedsMore};
use crate::session::{SessionData, StepResult};
use crate::validate::validations::SIMPLE;
use crate::Authentication;

#[derive(Debug)]
enum PlainError {
    BadFormat,
    BadAuthzid(Utf8Error),
    BadAuthcid(Utf8Error),
    BadPassword(Utf8Error),
    Saslprep(stringprep::Error),
}

impl Display for PlainError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadFormat => {
                f.write_str("invalid format, expected three strings separated by two NULL-bytes")
            }
            Self::BadAuthzid(e) => write!(f, "authzid is invalid UTF-8: {}", e),
            Self::BadAuthcid(e) => write!(f, "authcid is invalid UTF-8: {}", e),
            Self::BadPassword(e) => write!(f, "password is invalid UTF-8: {}", e),
            Self::Saslprep(e) => write!(f, "saslprep failed: {}", e),
        }
    }
}

impl From<stringprep::Error> for PlainError {
    fn from(e: Error) -> Self {
        Self::Saslprep(e)
    }
}

impl MechanismError for PlainError {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}

pub struct Plain;

impl Authentication for Plain {
    fn step(
        &mut self,
        session: &mut SessionData,
        input: Option<&[u8]>,
        _writer: &mut dyn Write,
    ) -> StepResult {
        if input.map(|buf| buf.len()).unwrap_or(0) == 0 {
            return Ok(NeedsMore(None));
        }

        let input = input.unwrap();
        let mut split = input.split(|byte| *byte == 0);
        let authzid: &[u8] = split.next().ok_or(PlainError::BadFormat)?;
        let authcid: &[u8] = split.next().ok_or(PlainError::BadFormat)?;
        let password: &[u8] = split.next().ok_or(PlainError::BadFormat)?;
        if split.next().is_some() {
            return Err(PlainError::BadFormat.into());
        }

        if !authzid.is_empty() {
            let s = std::str::from_utf8(authzid).map_err(PlainError::BadAuthzid)?;
            let authzidprep = saslprep(s).map_err(|e| PlainError::from(e))?.to_string();
            session.set_property::<AuthzId>(Arc::new(authzidprep));
        }

        let authcid = std::str::from_utf8(authcid).map_err(PlainError::BadAuthcid)?;
        let authcidprep = saslprep(authcid)
            .map_err(|e| PlainError::from(e))?
            .to_string();
        session.set_property::<AuthId>(Arc::new(authcidprep));

        let password = std::str::from_utf8(password).map_err(PlainError::BadPassword)?;
        let passwordprep = saslprep(password)
            .map_err(|e| PlainError::from(e))?
            .to_string();
        session.set_property::<Password>(Arc::new(passwordprep));

        session.validate(SIMPLE)?;
        Ok(Done(None))
    }
}
