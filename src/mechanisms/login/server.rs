use crate::alloc::string::String;
use crate::context::{Demand, DemandReply, Provider};
use crate::error::MechanismErrorKind;
use crate::mechanism::{Authentication, MechanismError};
use crate::prelude::SessionError;
use crate::property::{AuthId, Password};
use crate::session::{MechanismData, MessageSent, State};
use core::str::Utf8Error;
use core2::io::Write;
use thiserror::Error;

#[derive(Debug, Error)]
enum LoginError {
    #[error(transparent)]
    Utf8(Utf8Error),
}

impl MechanismError for LoginError {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}

#[derive(Debug)]
pub struct Login {
    state: LoginState,
}
#[derive(Debug, Eq, PartialEq)]
enum LoginState {
    New,
    WaitingForUsername,
    WaitingForPassword(String),
    Done,
}
impl Login {
    pub const fn new() -> Self {
        Self {
            state: LoginState::New,
        }
    }
}
impl Authentication for Login {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<State, SessionError> {
        match self.state {
            LoginState::New => {
                let out = b"User Name\0";
                writer.write_all(out)?;
                self.state = LoginState::WaitingForUsername;
                Ok(State::Running)
            }
            LoginState::WaitingForUsername => {
                if let Some(input) = input {
                    let username = core::str::from_utf8(input)
                        .map_err(LoginError::Utf8)?
                        .to_string();

                    let out = b"Password\0";
                    writer.write_all(out)?;
                    self.state = LoginState::WaitingForPassword(username);
                    Ok(State::Running)
                } else {
                    Err(SessionError::InputDataRequired)
                }
            }
            LoginState::WaitingForPassword(ref username) => {
                if let Some(input) = input {
                    struct LoginProvider<'a> {
                        authid: &'a str,
                        password: &'a [u8],
                    }
                    impl<'a> Provider<'a> for LoginProvider<'a> {
                        fn provide(&self, req: &mut Demand<'a>) -> DemandReply<()> {
                            req.provide_ref::<AuthId>(self.authid)?
                                .provide_ref::<Password>(self.password)?
                                .done()
                        }
                    }
                    let prov = LoginProvider {
                        authid: username.as_str(),
                        password: input,
                    };
                    session.validate(&prov)?;
                    self.state = LoginState::Done;
                    Ok(State::Finished(MessageSent::No))
                } else {
                    Err(SessionError::InputDataRequired)
                }
            }
            LoginState::Done => Err(SessionError::MechanismDone),
        }
    }
}
