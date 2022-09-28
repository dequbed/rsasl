use super::AnonymousToken;
use crate::context::ThisProvider;
use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::mechanism::Authentication;
use crate::session::{MechanismData, MessageSent, State};
use acid_io::Write;
use core::str::Utf8Error;
use thiserror::Error;

#[derive(Debug, Eq, PartialEq, Copy, Clone, Error)]
#[error("anonymous token received is invalid UTF-8 or longer than 255 chars")]
pub struct ParseError(Utf8Error);
impl MechanismError for ParseError {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Anonymous;
impl Authentication for Anonymous {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        _writer: &mut dyn Write,
    ) -> Result<State, SessionError> {
        // Treat an input of `None` like an empty slice. This is a gray zone in behaviour but can
        // not lead to loops since this mechanism will *always* return State::Finished.
        let input = core::str::from_utf8(input.unwrap_or(&[])).map_err(ParseError)?;
        // The input is not further validated and passed to the user as-is.
        session.validate(&ThisProvider::<AnonymousToken>::with(input))?;
        Ok(State::Finished(MessageSent::No))
    }
}

#[cfg(test)]
mod tests {
    use crate::callback::{Context, SessionCallback, SessionData};
    use crate::mechanisms::anonymous::AnonymousToken;
    use crate::test;
    use crate::validate::{Validate, ValidationError};
    use std::io::Cursor;

    #[derive(Default)]
    struct C<'a> {
        token: &'a str,
    }
    impl SessionCallback for C<'_> {
        fn validate(
            &self,
            _session_data: &SessionData,
            context: &Context,
            _validate: &mut Validate<'_>,
        ) -> Result<(), ValidationError> {
            let token = context.get_ref::<AnonymousToken>().unwrap();
            println!("expected: {:?} provided: {:?}", self.token, token);
            assert_eq!(token, self.token);
            Ok(())
        }
    }

    fn test_token(token: &'static str, input: &[u8]) {
        let config = test::server_config(C { token });
        let mut session = test::server_session(config, &super::super::mechinfo::ANONYMOUS);
        let mut out = Cursor::new(Vec::new());

        let state = session.step(Some(input), &mut out).unwrap();

        assert!(state.is_finished());
        assert!(!state.has_sent_message())
    }

    #[test]
    fn test_successful() {
        let tokens = ["", "thisisatesttoken"];
        for token in tokens {
            test_token(token, token.as_bytes());
        }
    }

    #[test]
    #[should_panic]
    fn test_reject_invalid_1() {
        test_token("token", b"");
    }

    #[test]
    #[should_panic]
    fn test_reject_invalid_2() {
        test_token("", b"someunexpectedtoken");
    }

    #[test]
    fn test_weird_utf8() {
        let tokens = ["«küßî»", "“ЌύБЇ”"];
        for token in tokens {
            test_token(token, token.as_bytes());
        }
    }

    #[test]
    // `None` input should read as empty token
    fn test_no_input() {
        let config = test::server_config(C { token: "" });
        let mut session = test::server_session(config, &super::super::mechinfo::ANONYMOUS);
        let mut out = Cursor::new(Vec::new());

        let state = session.step(None, &mut out).unwrap();

        assert!(state.is_finished());
        assert!(!state.has_sent_message());
    }
}
