use crate::context::EmptyProvider;
use crate::error::SessionError;
use crate::mechanism::{Authentication, MechanismData};
use crate::property::{AuthId, Password};
use crate::session::{MessageSent, State};
use acid_io::Write;

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
        Self {
            state: LoginState::Authid,
        }
    }
}
impl Authentication for Login {
    fn step(
        &mut self,
        session: &mut MechanismData,
        _input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<State, SessionError> {
        match self.state {
            LoginState::Authid => {
                session.need_with::<AuthId, _, _>(&EmptyProvider, |authid| {
                    writer.write_all(authid.as_bytes())?;
                    Ok(())
                })?;
                self.state = LoginState::Password;
                Ok(State::Running)
            }
            LoginState::Password => {
                session.need_with::<Password, _, _>(&EmptyProvider, |password| {
                    writer.write_all(password)?;
                    Ok(())
                })?;
                self.state = LoginState::Done;
                Ok(State::Finished(MessageSent::Yes))
            }
            LoginState::Done => Err(SessionError::MechanismDone),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::SASLConfig;
    use crate::mechanisms::login::mechinfo::LOGIN;
    use crate::test::client_session;
    use std::io::Cursor;

    #[test]
    fn simple_combination() {
        let config =
            SASLConfig::with_credentials(None, "testuser".to_string(), "password".to_string())
                .unwrap();
        let mut login = client_session(config, &LOGIN);
        let mut out = Cursor::new(Vec::new());

        assert!(login.step(None, &mut out).is_ok());
        assert_eq!(&out.get_ref()[..], b"testuser");

        let pos = out.position() as usize;

        assert!(login.step(None, &mut out).is_ok());
        assert_eq!(&(out.get_ref())[pos..], b"password");
    }
}
