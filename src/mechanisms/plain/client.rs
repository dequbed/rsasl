use crate::mechanism::Authentication;
use crate::session::{MechanismData, State};

use crate::callback::CallbackError;
use crate::context::EmptyProvider;
use crate::error::SessionError;
use std::io::Write;

use super::mechinfo::PlainError;
use crate::property::{AuthId, AuthzId, Password};

#[derive(Copy, Clone, Debug)]
pub struct Plain;

impl Authentication for Plain {
    fn step(
        &mut self,
        session: &mut MechanismData,
        _input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<(State, Option<usize>), SessionError> {
        let mut len = 0usize;
        let res = session.need_with::<AuthzId, _, _>(&EmptyProvider, &mut |authzid| {
            if authzid.contains('\0') {
                return Err(SessionError::MechanismError(Box::new(
                    PlainError::ContainsNull,
                )));
            }
            writer.write_all(authzid.as_bytes())?;
            len += authzid.len();
            Ok(())
        });
        match res {
            Ok(_) => {}
            Err(SessionError::CallbackError(_)) => {}
            Err(other) => return Err(other.into()),
        }
        len += writer.write(&[0])?;

        session.need_with::<AuthId, _, _>(&EmptyProvider, &mut |authid| {
            if authid.contains('\0') {
                return Err(SessionError::MechanismError(Box::new(
                    PlainError::ContainsNull,
                )));
            }
            writer.write_all(authid.as_bytes())?;
            len += authid.len();
            Ok(())
        })?;
        len += writer.write(&[0])?;

        session.need_with::<Password, _, _>(&EmptyProvider, &mut |password| {
            writer.write_all(password)?;
            len += password.len();
            Ok(())
        })?;

        Ok((State::Finished, Some(len)))
    }
}
