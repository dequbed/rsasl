use crate::context::EmptyProvider;
use crate::error::SessionError;
use crate::mechanism::Authentication;
use crate::property::AuthzId;
use crate::session::{MechanismData, MessageSent, State};
use core2::io::Write;

#[derive(Copy, Clone, Debug)]
pub struct External;

impl Authentication for External {
    fn step(
        &mut self,
        session: &mut MechanismData,
        _input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<State, SessionError> {
        session.maybe_need_with::<AuthzId, _, _>(&EmptyProvider, |authzid| {
            writer.write_all(authzid.as_bytes())?;
            Ok(())
        })?;

        Ok(State::Finished(MessageSent::Yes))
    }
}

#[cfg(test)]
mod tests {
    use crate::callback::{Context, Request, SessionCallback, SessionData};
    use crate::error::SessionError;
    use crate::property::AuthzId;
    use crate::test;
    use std::io::Cursor;

    struct C<'a> {
        authzid: Option<&'a str>,
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

            Ok(())
        }
    }

    fn test_authzid(authzid: Option<&'static str>, output: &[u8]) {
        let config = test::server_config(C { authzid });
        let mut session = test::client_session(config, &super::super::mechinfo::EXTERNAL);
        let mut out = Cursor::new(Vec::new());

        let state = session.step(None, &mut out).unwrap();

        let data = out.into_inner();
        assert_eq!(output, &data[..]);
        assert!(state.is_finished());
    }

    #[test]
    fn test_external() {
        let authzids = [
            "", // empty authzid should not error
            "heylookanauthzid",
            "cn=this,ou=authzid,ou=has,o=weirdformatting",
            "«küßî»",
            "“ЌύБЇ”",
        ];
        for authzid in authzids {
            test_authzid(Some(authzid), authzid.as_bytes());
        }
    }

    #[test]
    fn test_no_authzid() {
        test_authzid(None, b"");
    }
}
