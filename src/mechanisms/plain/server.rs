use std::io::Write;

use stringprep::saslprep;

use super::mechinfo::PlainError;
use crate::context::{Demand, DemandReply, Provider};
use crate::error::SessionError;
use crate::mechanism::Authentication;
use crate::property::{AuthId, AuthzId, Password};
use crate::session::{MechanismData, State};

pub struct Plain;
#[derive(Debug)]
pub struct PlainProvider<'a> {
    pub authcid: &'a str,
    pub authzid: Option<&'a str>,
    pub password: &'a [u8],
}
impl<'a> Provider<'a> for PlainProvider<'a> {
    fn provide(&self, req: &mut Demand<'a>) -> DemandReply<()> {
        req.provide_ref::<AuthId>(self.authcid)?
            .provide_ref::<Password>(self.password)?;

        if let Some(authzid) = self.authzid {
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
    ) -> Result<(State, Option<usize>), SessionError> {
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
            authzid: authzid.as_deref(),
            authcid: authcid.as_ref(),
            password: password.as_bytes(),
        };

        session.validate(&provider)?;
        Ok((State::Finished, None))
    }
}
