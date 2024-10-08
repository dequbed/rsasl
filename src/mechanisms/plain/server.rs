use super::mechinfo::PlainError;
use crate::context::{Demand, DemandReply, Provider};
use crate::error::SessionError;
use crate::mechanism::Authentication;
use crate::property::{AuthId, AuthzId, Password};
use crate::session::{MechanismData, MessageSent, State};
use core2::io::Write;
use stringprep::saslprep;

#[derive(Debug)]
pub struct PlainProvider<'a> {
    pub authcid: &'a str,
    pub authzid: &'a str,
    pub password: &'a [u8],
}
impl<'a> Provider<'a> for PlainProvider<'a> {
    fn provide(&self, req: &mut Demand<'a>) -> DemandReply<()> {
        req.provide_ref::<AuthId>(self.authcid)?
            .provide_ref::<Password>(self.password)?
            .provide_ref::<AuthzId>(self.authzid)?
            .done()
    }
}

pub struct Plain;
impl Authentication for Plain {
    #[allow(clippy::similar_names)]
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        _writer: &mut dyn Write,
    ) -> Result<State, SessionError> {
        let input = input.ok_or(SessionError::InputDataRequired)?;

        if input.len() < 4 {
            return Err(PlainError::BadFormat.into());
        }
        // split on NUL byte
        let mut split = input.split(|byte| *byte == 0);

        let authzid: &[u8] = split.next().ok_or(PlainError::BadFormat)?;
        let authcid: &[u8] = split.next().ok_or(PlainError::BadFormat)?;
        let password: &[u8] = split.next().ok_or(PlainError::BadFormat)?;

        // If we have three or more null bytes this will be Some and return an error
        if split.next().is_some() {
            return Err(PlainError::BadFormat.into());
        }

        let authzid = core::str::from_utf8(authzid).map_err(PlainError::BadAuthzid)?;
        let authcid = core::str::from_utf8(authcid).map_err(PlainError::BadAuthcid)?;
        let authcid = saslprep(authcid).map_err(PlainError::Saslprep)?;

        if authcid.is_empty() {
            return Err(PlainError::Empty.into());
        }

        if let Ok(password) = core::str::from_utf8(password) {
            let password = saslprep(password).map_err(PlainError::Saslprep)?;

            if password.is_empty() {
                return Err(PlainError::Empty.into());
            }

            let provider = PlainProvider {
                authzid,
                authcid: authcid.as_ref(),
                password: password.as_bytes(),
            };

            session.validate(&provider)?;
        } else {
            if password.is_empty() {
                return Err(PlainError::Empty.into());
            }

            let provider = PlainProvider {
                authzid,
                authcid: authcid.as_ref(),
                password,
            };

            session.validate(&provider)?;
        };

        Ok(State::Finished(MessageSent::No))
    }
}
