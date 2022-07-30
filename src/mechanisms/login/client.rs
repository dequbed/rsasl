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
pub(super) struct Login {
    state: LoginState,
}
impl Login {
    pub(crate) fn new() -> Self {
        Self { state: LoginState::Authid }
    }
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
                self.state = LoginState::Password;
                Ok((State::Running, Some(len)))
            }
            LoginState::Password => {
                let len = session.need_with::<Password, _, _>(&EmptyProvider, &mut |password| {
                    writer.write_all(password)?;
                    Ok(password.len())
                })?;
                self.state = LoginState::Done;
                Ok((State::Finished, Some(len)))
            }
            LoginState::Done => {
                Err(SessionError::MechanismDone)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;
    use crate::config::SASLConfig;
    use crate::mechanisms::login::mechinfo::LOGIN;
    use crate::sasl::SASLClient;
    use crate::session::{Session, Side};
    use crate::test::test_client_session;
    use super::*;

    #[test]
    fn simple_combination() {
        let config = SASLConfig::with_credentials(None, "testuser".to_string(), "password".to_string())
            .unwrap();
        let mut login = test_client_session(config, &LOGIN);
        let mut out = Cursor::new(Vec::new());

        assert!(login.step(None, &mut out).is_ok());
        assert_eq!(&out.get_ref()[..], b"testuser");

        let pos = out.position() as usize;

        assert!(login.step(None, &mut out).is_ok());
        assert_eq!(&(out.get_ref())[pos..], b"password");
    }
}