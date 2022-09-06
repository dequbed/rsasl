use crate::alloc::boxed::Box;
use crate::context::EmptyProvider;
use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::mechanism::{Authentication, MechanismData, State};
use crate::mechanisms::xoauth2::properties::XOAuth2Error;
use crate::property::{AuthId, OAuthBearerToken};
use crate::vectored_io::VectoredWriter;
use acid_io::Write;
use thiserror::Error;
use crate::session::MessageSent;

#[derive(Debug, Default)]
pub struct XOAuth2 {
    state: XOAuth2State,
}

#[derive(Debug)]
enum XOAuth2State {
    Initial,
    WaitingServerResponse,
    Done,
}

impl Default for XOAuth2State {
    fn default() -> Self {
        Self::Initial
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("response message is invalid UTF-8")]
    Utf8(
        #[from]
        #[source]
        core::str::Utf8Error,
    ),
}
impl MechanismError for Error {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}

impl Authentication for XOAuth2 {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        mut writer: &mut dyn Write,
    ) -> Result<State, SessionError> {
        match self.state {
            XOAuth2State::Initial => {
                session.need_with::<AuthId, _, _>(&EmptyProvider, |authid| {
                    let data = [b"user=", authid.as_bytes(), b"\x01auth=Bearer "];
                    let mut vecw = VectoredWriter::new(data);
                    vecw.write_all_vectored(&mut writer)?;
                    Ok(())
                })?;

                session.need_with::<OAuthBearerToken, _, _>(&EmptyProvider, |token| {
                    let data = [token.as_bytes(), b"\x01\x01"];
                    let mut vecw = VectoredWriter::new(data);
                    vecw.write_all_vectored(writer)?;
                    Ok(())
                })?;

                self.state = XOAuth2State::WaitingServerResponse;

                Ok(State::Running)
            }
            XOAuth2State::WaitingServerResponse => {
                // whatever happens, afterwards this mechanisms won't be stepable again, so we
                // can set to done right here too
                self.state = XOAuth2State::Done;

                let input = input.unwrap_or(&[]);
                // Empty case is specifically *no error message*. So yeah, that's finished then?
                // Most protocols will indicate success via the protocol immediately so this
                // should only be hit if we get protocol handlers being overly cautious and
                // calling step in that case too. Which, granted, is a good thing! We want that!
                if input.is_empty() {
                    return Ok(State::Finished(MessageSent::No));
                }

                // We can't exactly validate much of the error response so let the user
                // callback handle that.
                let error = core::str::from_utf8(input)
                    .map_err(|error| SessionError::MechanismError(Box::new(Error::Utf8(error))))?;
                // If the user callback *doesn't*, we must error, so '?' is correct.
                session.action::<XOAuth2Error>(&EmptyProvider, error)?;
                Ok(State::Finished(MessageSent::Yes))
            }
            XOAuth2State::Done => Err(SessionError::MechanismDone),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callback::{Context, Request, SessionCallback, SessionData};

    use crate::session::Session;
    use crate::test;

    use std::io::Cursor;

    struct C<'a> {
        authid: &'a str,
        token: &'a str,
        expected_error: Option<&'a [u8]>,
    }

    impl SessionCallback for C<'_> {
        fn callback(
            &self,
            _session_data: &SessionData,
            _context: &Context,
            request: &mut Request,
        ) -> Result<(), SessionError> {
            request
                .satisfy::<AuthId>(self.authid)?
                .satisfy::<OAuthBearerToken>(self.token)?;

            // Explicitly do not handle an error if it wasn't expected so a `NoCallback` error is
            // returned.
            if let Some(expected) = self.expected_error {
                if let Some(error) = request.get_action::<XOAuth2Error>() {
                    assert_eq!(error.as_bytes(), expected)
                }
            }

            Ok(())
        }
    }

    impl Default for C<'static> {
        fn default() -> Self {
            Self {
                authid: "username@host.tld",
                token: "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg",
                expected_error: None,
            }
        }
    }

    fn prepare_session(callback: C<'static>) -> Session {
        let _authid = "username@host.tld";
        let _token = "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg";
        let config = test::client_config(callback);
        test::client_session(config, &super::super::mechinfo::XOAUTH2)
    }

    #[test]
    fn test_xoauth2() {
        let mut session = prepare_session(C::default());
        let mut out = Cursor::new(Vec::new());
        let state = session.step(None, &mut out).unwrap();
        let data = out.into_inner();
        assert!(state.is_running());
        assert!(state.has_sent_message());
        assert_eq!(
            &data[..],
            b"user=username@host.tld\x01auth=Bearer ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg\x01\x01"
        );
    }

    #[test]
    /// XOAUTH2 should treat a second step with both `None` and `Some(&[])` as auth ok and not err.
    fn test_auth_ok_behaviour_none() {
        let mut session = prepare_session(C::default());

        let mut out = Cursor::new(Vec::new());
        let state = session.step(None, &mut out).unwrap();
        assert!(state.is_running());
        assert!(state.has_sent_message());

        // second call to step, with None as input again. This should not error.
        let state = session.step(None, &mut out).unwrap();
        assert!(state.is_finished());
        assert!(!state.has_sent_message());
    }

    #[test]
    /// XOAUTH2 should treat a second step with both `None` and `Some(&[])` as auth ok and not err.
    fn test_auth_ok_behaviour_some_empty() {
        let mut session = prepare_session(C::default());

        let mut out = Cursor::new(Vec::new());
        let state = session.step(None, &mut out).unwrap();
        assert!(state.is_running());
        assert!(state.has_sent_message());

        // second call to step, with None as input again. This should not error.
        let state = session.step(Some(&[]), &mut out).unwrap();
        assert!(state.is_finished());
        assert!(!state.has_sent_message());
    }

    #[test]
    fn test_auth_fail_finishes() {
        let error_input =
            br#"{"status":"401","schemes":"bearer","scope":"https://mail.google.com/"}"#;

        let mut session = prepare_session(C {
            expected_error: Some(error_input),
            ..Default::default()
        });

        let mut out = Cursor::new(Vec::new());
        let state = session.step(None, &mut out).unwrap();
        assert!(state.is_running());
        assert!(state.has_sent_message());

        // second call to step, with None as input again. This should not error.
        let state = session.step(Some(error_input), &mut out).unwrap();
        assert!(state.is_finished());
        assert!(!state.has_sent_message());
    }
}
