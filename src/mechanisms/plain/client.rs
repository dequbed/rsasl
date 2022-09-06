use crate::alloc::boxed::Box;
use crate::mechanism::Authentication;
use crate::session::{MechanismData, MessageSent, State};

use crate::context::EmptyProvider;
use crate::error::SessionError;
use acid_io::Write;

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
    ) -> Result<State, SessionError> {
        session
            .maybe_need_with::<AuthzId, _, _>(&EmptyProvider, |authzid| {
                if authzid.contains('\0') {
                    return Err(SessionError::MechanismError(Box::new(
                        PlainError::ContainsNull,
                    )));
                }
                writer.write_all(authzid.as_bytes())?;
                Ok(())
            })?;

        writer.write_all(&[0])?;

        session.need_with::<AuthId, _, _>(&EmptyProvider, |authid| {
            if authid.is_empty() {
                return Err(SessionError::MechanismError(Box::new(PlainError::Empty)));
            }
            if authid.contains('\0') {
                return Err(SessionError::MechanismError(Box::new(
                    PlainError::ContainsNull,
                )));
            }
            writer.write_all(authid.as_bytes())?;
            Ok(())
        })?;

        writer.write_all(&[0])?;

        session.need_with::<Password, _, _>(&EmptyProvider, |password| {
            if password.is_empty() {
                return Err(SessionError::MechanismError(Box::new(PlainError::Empty)));
            }
            if password.contains(&0u8) {
                return Err(SessionError::MechanismError(Box::new(
                    PlainError::ContainsNull,
                )));
            }
            writer.write_all(password)?;
            Ok(())
        })?;

        Ok(State::Finished(MessageSent::Yes))
    }
}

#[cfg(test)]
mod tests {
    use crate::callback::{Context, Request, SessionCallback, SessionData};
    use crate::error::SessionError;
    use crate::mechanisms::plain::mechinfo::PlainError;
    use crate::property::{AuthId, AuthzId, Password};
    use crate::session::State;
    use crate::test;
    use std::io::Cursor;

    struct C<'a> {
        authzid: Option<&'a str>,
        authid: &'a str,
        // yes, password must actually be UTF-8. But we specify a non-unicode behaviour too so we
        // need to test it.
        password: &'a [u8],
    }
    impl SessionCallback for C<'_> {
        fn callback(
            &self,
            _session_data: &SessionData,
            _context: &Context,
            request: &mut Request,
        ) -> Result<(), SessionError> {
            if let Some(authzid) = self.authzid {
                request.satisfy::<AuthzId>(authzid)?;
            }

            request
                .satisfy::<AuthId>(self.authid)?
                .satisfy::<Password>(self.password)?;

            Ok(())
        }
    }

    fn test(
        authzid: Option<&'static str>,
        authid: &'static str,
        password: &'static [u8],
        output: &[u8],
    ) {
        let (state, data) = test_result(authzid, authid, password).unwrap();
        assert_eq!(output, &data[..]);
        assert!(state.is_finished());
    }

    fn test_error(
        authzid: Option<&'static str>,
        authid: &'static str,
        password: &'static [u8],
        matches: impl FnOnce(SessionError) -> bool,
    ) {
        let error = test_result(authzid, authid, password).unwrap_err();
        assert!(matches(error))
    }

    fn test_result(
        authzid: Option<&'static str>,
        authid: &'static str,
        password: &'static [u8],
    ) -> Result<(State, Vec<u8>), SessionError> {
        let config = test::server_config(C {
            authzid,
            authid,
            password,
        });
        let mut session = test::client_session(config, &super::super::mechinfo::PLAIN);
        let mut out = Cursor::new(Vec::new());

        let state = session.step(None, &mut out)?;

        let data = out.into_inner();

        Ok((state, data))
    }

    #[test]
    fn test_simple_plain() {
        let parts = [
            (None, "testuser", "secret", "\0testuser\0secret"),
            (
                Some("authzid"),
                "testuser",
                "secret",
                "authzid\0testuser\0secret",
            ),
            (None, "«küßî»", "“ЌύБЇ”", "\0«küßî»\0“ЌύБЇ”"),
        ];
        for (authzid, authid, password, output) in parts {
            test(authzid, authid, password.as_bytes(), output.as_bytes())
        }
    }

    #[test]
    fn reject_null_bytes() {
        fn m(error: SessionError) -> bool {
            match error {
                SessionError::MechanismError(mecherror) => {
                    let expected = format!("{}", PlainError::ContainsNull);
                    let rendered = format!("{}", mecherror);
                    expected.as_str() == rendered.as_str()
                }
                _ => false,
            }
        }

        test_error(Some("authzid\0containsnull"), "authid", b"password", m);
        test_error(Some("authzid"), "auth\0id", b"password", m);
        test_error(Some("authzid"), "authid", b"pass\0word", m);
    }

    #[test]
    fn password_as_is() {
        let password = &[0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF];
        test(None, "a", password, b"\0a\0\x80\xC0\xE0\xF0\xF8\xFC\xFE\xFF");
    }

    #[test]
    fn reject_empty_authid_password() {
        fn m(error: SessionError) -> bool {
            match error {
                SessionError::MechanismError(mecherror) => {
                    let expected = format!("{}", PlainError::Empty);
                    let rendered = format!("{}", mecherror);
                    expected.as_str() == rendered.as_str()
                }
                _ => false,
            }
        }
        test_error(None, "", b"password", m);
        test_error(None, "authid", b"", m);
    }

    #[test]
    fn empty_authzid_is_no_authzid() {
        let output = b"\0authid\0password";
        test(Some(""), "authid", b"password", output);
        test(None, "authid", b"password", output);
    }
}
