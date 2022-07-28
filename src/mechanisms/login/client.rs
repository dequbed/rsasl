use crate::context::EmptyProvider;
use std::io::Write;
use crate::error::SessionError;
use crate::mechanism::{Authentication, MechanismData, StepResult};
use crate::property::{AuthId, Password};
use crate::session::State;

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
enum LoginState {
    Authid,
    Password,
    Done,
}
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
struct Login {
    state: LoginState,
}
impl Authentication for Login {
    fn step(
        &mut self,
        session: &mut MechanismData,
        _input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> StepResult {
        match self.state {
            LoginState::Authid => {
                let len = session.need_with::<AuthId, _, _>(&EmptyProvider, &mut |authid| {
                    writer.write_all(authid.as_bytes())?;
                    Ok(authid.len())
                })?;
                Ok((State::Running, Some(len)))
            }
            LoginState::Password => {
                let len = session.need_with::<Password, _, _>(&EmptyProvider, &mut |password| {
                    writer.write_all(password.as_bytes())?;
                    Ok(authid.len())
                })?;
                Ok((State::Finished, Some(len)))
            }
            LoginState::Done => {
                Err(SessionError::MechanismDone)
            }
        }
    }
}