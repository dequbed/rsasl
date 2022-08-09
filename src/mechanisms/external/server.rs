use core::str::Utf8Error;
use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::mechanism::Authentication;
use thiserror::Error;

use crate::context::{EmptyProvider, ThisProvider};
use crate::property::AuthzId;
use crate::session::{MechanismData, State};
use std::io::Write;

#[derive(Debug, Eq, PartialEq, Copy, Clone, Error)]
#[error("the given external token is invalid UTF-8")]
pub struct ParseError(#[source] Utf8Error);
impl MechanismError for ParseError {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}

#[derive(Copy, Clone, Debug)]
pub struct External;

impl Authentication for External {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        _writer: &mut dyn Write,
    ) -> Result<(State, Option<usize>), SessionError> {
        let input = input.unwrap_or(&[]);
        let authzid = core::str::from_utf8(input).map_err(ParseError)?;
        session.validate(&ThisProvider::<AuthzId>::with(authzid))?;
        Ok((State::Finished, None))
    }
}

#[cfg(test)]
mod tests {
    use crate::callback::{Context, Request, SessionCallback, SessionData};
    use crate::error::SessionError;
    use crate::test;
    use crate::validate::{Validate, ValidationError};
    use std::io::Cursor;
    use crate::property::AuthzId;

    struct C<'a> {
        authzid: &'a str,
    }
    impl SessionCallback for C<'_> {
        fn validate(
            &self,
            _session_data: &SessionData,
            context: &Context,
            _validate: &mut Validate<'_>,
        ) -> Result<(), ValidationError> {
            let authzid = context.get_ref::<AuthzId>().unwrap();
            println!("expected: {:?} provided: {:?}", self.authzid, authzid);
            assert_eq!(authzid, self.authzid);
            Ok(())
        }
    }
    impl Default for C<'static> {
        fn default() -> Self {
            Self { authzid: "" }
        }
    }

    fn test_token(authzid: &'static str, input: &[u8]) {
        let config = test::server_config(C { authzid });
        let mut session = test::server_session(config, &super::super::mechinfo::EXTERNAL);
        let mut out = Cursor::new(Vec::new());

        let (state, written) = session.step(Some(input), &mut out).unwrap();

        assert!(state.is_finished());
        assert!(written.is_none());
    }

    #[test]
    fn test_successful() {
        let authzids = [
            "", // empty authzid should not error
            "heylookanauthzid",
            "cn=this,ou=authzid,ou=has,o=weirdformatting",
            "«küßî»",
            "“ЌύБЇ”",
        ];
        for authzid in authzids {
            test_token(authzid, authzid.as_bytes());
        }
    }

    #[test]
    #[should_panic]
    fn test_reject_invalid_1() {
        test_token("expectedauthzid", b"");
    }

    #[test]
    #[should_panic]
    fn test_reject_invalid_2() {
        test_token("", b"someunexpectedauthzid");
    }

    #[test]
    // `None` input should read as empty token
    fn test_no_input() {
        let config = test::server_config(C::default());
        let mut session = test::server_session(config, &super::super::mechinfo::EXTERNAL);
        let mut out = Cursor::new(Vec::new());

        let (state, written) = session.step(None, &mut out).unwrap();

        assert!(state.is_finished());
        assert!(written.is_none());
    }
}