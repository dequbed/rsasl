use crate::alloc::boxed::Box;
use crate::context::{Demand, DemandReply, Provider};
use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::mechanism::{Authentication, MechanismData, State};
use crate::mechanisms::xoauth2::properties::XOAuth2Validate;
use crate::property::{AuthId, OAuthBearerToken};
use crate::session::MessageSent;
use core::str::Utf8Error;
use core2::io::Write;
use thiserror::Error;

#[derive(Debug, Clone, Default)]
pub struct XOAuth2 {
    state: XOAuth2State,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum XOAuth2State {
    Initial,
    Errored,
}

impl Default for XOAuth2State {
    fn default() -> Self {
        Self::Initial
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("provided {0} is not UTF-8 encoded")]
    // save a tiny bit of .text data by using one impl for both ;)
    NotUtf8(&'static str, #[source] Utf8Error),

    #[error("input is of an invalid format")]
    InvalidFormat,
}
impl MechanismError for Error {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}

const USER: &str = "username";
const TOKN: &str = "bearer token";

// parts are delimited by `^A` which is ASCII SOH with byte value 1
const ASCII_SOH: u8 = 1u8;

struct Prov<'a> {
    authid: &'a str,
    token: &'a str,
}
impl<'a> Provider<'a> for Prov<'a> {
    fn provide(&self, req: &mut Demand<'a>) -> DemandReply<()> {
        req.provide_ref::<AuthId>(self.authid)?
            .provide_ref::<OAuthBearerToken>(self.token)?
            .done()
    }
}

impl Authentication for XOAuth2 {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<State, SessionError> {
        match self.state {
            XOAuth2State::Initial => {
                let input = input.ok_or(SessionError::InputDataRequired)?;

                let mid = input
                    .iter()
                    .position(|b| *b == ASCII_SOH)
                    .ok_or_else(|| SessionError::MechanismError(Box::new(Error::InvalidFormat)))?;

                let (userpart, tokenpart) = input.split_at(mid);

                let raw_authid = userpart
                    .strip_prefix(b"user=")
                    .ok_or_else(|| SessionError::MechanismError(Box::new(Error::InvalidFormat)))?;

                let raw_token = tokenpart
                    .strip_prefix(b"\x01auth=Bearer ")
                    .and_then(|token| token.strip_suffix(b"\x01\x01"))
                    .ok_or_else(|| SessionError::MechanismError(Box::new(Error::InvalidFormat)))?;

                let authid = core::str::from_utf8(raw_authid)
                    .map_err(|e| SessionError::MechanismError(Box::new(Error::NotUtf8(USER, e))))?;

                let token = core::str::from_utf8(raw_token)
                    .map_err(|e| SessionError::MechanismError(Box::new(Error::NotUtf8(TOKN, e))))?;

                let prov = Prov { authid, token };

                // if the mechanism has one step or three depends on if the token is valid or not.
                let state = session.need_with::<XOAuth2Validate, _, _>(&prov, |result| {
                    if let Err(error) = result {
                        writer.write_all(error.as_bytes())?;
                        self.state = XOAuth2State::Errored;
                        Ok(State::Running)
                    } else {
                        Ok(State::Finished(MessageSent::No))
                    }
                })?;

                // Let the user callback validate. This must be called no matter what `need_with`
                // above returned as the callback will likely need to generate an Error for the
                // protocol crate if the token was invalid.
                session.validate(&prov)?;

                Ok(state)
            }
            // This will ignore any input data. input *should* be nothing or an empty slice, so a
            // misbehaving client implementation can still be accepted.
            XOAuth2State::Errored => Ok(State::Finished(MessageSent::No)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callback::{Request, SessionCallback};
    use crate::context::Context;
    use crate::session::{Session, SessionData};
    use crate::test;
    use std::io::Cursor;

    struct C<'a> {
        authid: &'a str,
        token: &'a str,
        result: Result<(), &'a str>,
    }

    impl SessionCallback for C<'_> {
        fn callback(
            &self,
            _session_data: &SessionData,
            context: &Context,
            request: &mut Request,
        ) -> Result<(), SessionError> {
            if request.is::<XOAuth2Validate>() {
                assert_eq!(context.get_ref::<AuthId>(), Some(self.authid));
                assert_eq!(context.get_ref::<OAuthBearerToken>(), Some(self.token));

                request.satisfy::<XOAuth2Validate>(&self.result)?;
            }

            Ok(())
        }
    }

    impl Default for C<'static> {
        fn default() -> Self {
            Self {
                authid: "username@host.tld",
                token: "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg",
                result: Ok(()),
            }
        }
    }

    fn prepare_session(callback: C<'static>) -> Session {
        // let _authid = "username@host.tld";
        // let _token = "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg";
        let config = test::server_config(callback);
        test::server_session(config, &super::super::mechinfo::XOAUTH2)
    }

    #[test]
    fn test_successful() {
        let mut session = prepare_session(C::default());
        let mut out = Cursor::new(Vec::new());

        let data = b"user=username@host.tld\x01auth=Bearer ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg\x01\x01";
        let state = session.step(Some(data), &mut out).unwrap();

        assert!(state.is_finished());
        assert!(!state.has_sent_message());
    }

    #[test]
    fn test_errored() {
        let errstr = r#"{"status":"401","schemes":"bearer","scope":"https://mail.google.com/"}"#;
        let result = Err(errstr);
        let mut session = prepare_session(C {
            result,
            ..Default::default()
        });
        let mut out = Cursor::new(Vec::<u8>::new());

        let data = b"user=username@host.tld\x01auth=Bearer ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg\x01\x01";
        let state = session.step(Some(data), &mut out).unwrap();

        let data = out.into_inner();

        assert!(state.is_running());
        assert!(state.has_sent_message());
        assert_eq!(&data[..], errstr.as_bytes());
    }
}
