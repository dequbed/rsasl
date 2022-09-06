use crate::context::EmptyProvider;
use crate::error::SessionError;
use crate::mechanism::Authentication;
use crate::session::{MechanismData, MessageSent, State};
use acid_io::Write;
use super::AnonymousToken;

#[derive(Copy, Clone, Debug)]
pub struct Anonymous;
impl Authentication for Anonymous {
    fn step(
        &mut self,
        session: &mut MechanismData,
        _input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<State, SessionError> {
        session.maybe_need_with::<AnonymousToken, _, _>(&EmptyProvider, |token| {
            writer.write_all(token.as_bytes())?;
            Ok(())
        })?;
        Ok(State::Finished(MessageSent::Yes))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use crate::callback::{Context, Request, SessionCallback, SessionData};
    use crate::error::SessionError;
    use crate::mechanisms::anonymous::AnonymousToken;
    use crate::test;

    struct C<'a> {
        token: Option<&'a str>,
    }
    impl SessionCallback for C<'_> {
        fn callback(
            &self,
            _session_data: &SessionData,
            context: &Context,
            request: &mut Request,
        ) -> Result<(), SessionError> {
            if let Some(token) = self.token {
                request.satisfy::<AnonymousToken>(token)?;
            }

            Ok(())
        }
    }

    fn test_token(token: Option<&'static str>, output: &[u8]) {
        let config = test::server_config(C { token });
        let mut session = test::client_session(config, &super::super::mechinfo::ANONYMOUS);
        let mut out = Cursor::new(Vec::new());

        let (state, written) = session.step(None, &mut out).unwrap();

        let data = out.into_inner();
        assert_eq!(written, Some(data.len()));
        assert_eq!(output, &data[..]);
        assert!(state.is_finished());
    }

    #[test]
    fn test_with_token() {
        let tokens = [
            "thisisatoken",
            "", // empty string should not error.
        ];
        for token in tokens {
            test_token(Some(token), token.as_bytes());
        }
    }

    #[test]
    fn test_no_token() {
        test_token(None, b"");
    }
}