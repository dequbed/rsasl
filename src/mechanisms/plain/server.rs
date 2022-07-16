use std::borrow::Cow;

use std::io::Write;
use std::str::Utf8Error;
use thiserror::Error;

use stringprep::saslprep;

use crate::error::{MechanismError, MechanismErrorKind};

use crate::session::{MechanismData, State, StepResult};

use crate::context::{Demand, DemandReply, Provider};

use crate::property::{AuthId, AuthzId, Password, Property};
use crate::validate::{Validation};
use crate::Authentication;

#[derive(Debug, Error)]
enum PlainError {
    #[error("invalid format, expected three strings separated by two NULL-bytes")]
    BadFormat,
    #[error("authzid is invalid UTF-8: {0}")]
    BadAuthzid(#[source] Utf8Error),
    #[error("authcid is invalid UTF-8: {0}")]
    BadAuthcid(#[source] Utf8Error),
    #[error("password is invalid UTF-8: {0}")]
    BadPassword(#[source] Utf8Error),
    #[error("saslprep failed: {0}")]
    Saslprep(
        #[from]
        #[source]
        stringprep::Error,
    ),
}

impl MechanismError for PlainError {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}

pub struct Plain;
#[derive(Debug)]
pub struct PlainProvider<'a> {
    pub authcid: Cow<'a, str>,
    pub authzid: Option<Cow<'a, str>>,
    pub password: &'a [u8],
}
impl<'b> Provider for PlainProvider<'b> {
    fn provide<'a>(&'a self, req: &mut Demand<'a>) -> DemandReply<()> {
        req.provide_ref::<AuthId>(&self.authcid)?
            .provide_ref::<Password>(&self.password)?;

        if let Some(authzid) = self.authzid.as_ref() {
            req.provide_ref::<AuthzId>(authzid)?;
        }

        req.done()
    }
}

impl Authentication for Plain {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        _writer: &mut dyn Write,
    ) -> StepResult {
        if input.map(|buf| buf.len()).unwrap_or(0) < 4 {
            return Err(PlainError::BadFormat.into());
        }

        let input = input.unwrap();
        let mut split = input.split(|byte| *byte == 0);
        let authzid: &[u8] = split.next().ok_or(PlainError::BadFormat)?;
        let authcid: &[u8] = split.next().ok_or(PlainError::BadFormat)?;
        let password: &[u8] = split.next().ok_or(PlainError::BadFormat)?;
        if split.next().is_some() {
            return Err(PlainError::BadFormat.into());
        }

        let authzid = if !authzid.is_empty() {
            let s = std::str::from_utf8(authzid).map_err(PlainError::BadAuthzid)?;
            Some(saslprep(s).map_err(|e| PlainError::from(e))?)
        } else {
            None
        };

        let authcid = std::str::from_utf8(authcid).map_err(PlainError::BadAuthcid)?;
        let authcid = saslprep(authcid).map_err(|e| PlainError::from(e))?;

        let password = std::str::from_utf8(password).map_err(PlainError::BadPassword)?;
        let password = saslprep(password).map_err(|e| PlainError::from(e))?;

        let provider = PlainProvider {
            authzid,
            authcid,
            password: password.as_bytes(),
        };

        session.validate(&provider)?;
        Ok((State::Finished, None))
    }
}
