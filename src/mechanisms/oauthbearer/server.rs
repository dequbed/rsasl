use alloc::io::Write;
use crate::context::{Demand, DemandReply, Provider};
use crate::error::SessionError;
use crate::mechanism::{Authentication, MechanismData, State};
use crate::mechanisms::oauthbearer::properties::{OAuthBearerError, OAuthBearerValidate};
use crate::mechanisms::oauthbearer::parser::OAuthBearerMsg;
use crate::property::{AuthzId, OAuthBearerToken, OAuthBearerKV};
use crate::session::MessageSent;

#[derive(Debug, Clone, Default)]
pub struct OAuthBearer {
    state: OAuthBearerState,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum OAuthBearerState {
    Initial,
    Errored,
}
impl Default for OAuthBearerState {
    fn default() -> Self {
        Self::Initial
    }
}

impl Authentication for OAuthBearer {
    fn step(&mut self, session: &mut MechanismData, input: Option<&[u8]>, writer: &mut dyn Write) -> Result<State, SessionError> {
        match self.state {
            OAuthBearerState::Initial => {
                let input = input.ok_or(SessionError::InputDataRequired)?;

                let OAuthBearerMsg {
                    authzid, token, fields
                } = OAuthBearerMsg::parse(input).map_err(OAuthBearerError::Parse)?;

                struct Prov<'a> {
                    pub authzid: Option<&'a str>,
                    pub token: &'a str,
                    pub kvpairs: &'a [(&'a str, &'a str)],
                }
                impl<'a> Provider<'a> for Prov<'a> {
                    fn provide(&self, req: &mut Demand<'a>) -> DemandReply<()> {
                        if let Some(authzid) = self.authzid {
                            req.provide_ref::<AuthzId>(authzid)?;
                        }
                        req.provide_ref::<OAuthBearerToken>(self.token)?
                            .provide_ref::<OAuthBearerKV>(self.kvpairs)?
                            .done()
                    }
                }

                let prov = Prov { authzid, token, kvpairs: fields.as_slice() };

                let state = session.need_with::<OAuthBearerValidate, _, _>(&prov, |result| {
                    if let Err(error) = result {
                        serde_json::to_writer(writer, error).map_err(OAuthBearerError::Serialize)?;
                        self.state = OAuthBearerState::Errored;
                        Ok(State::Running)
                    } else {
                        Ok(State::Finished(MessageSent::No))
                    }
                })?;

                session.validate(&prov)?;

                Ok(state)
            }
            // This will ignore any input data. input *should* be nothing or an empty slice, so a
            // misbehaving client implementation can still be accepted.
            OAuthBearerState::Errored => Ok(State::Finished(MessageSent::No))
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
    use crate::mechanisms::oauthbearer::properties::OAuthBearerValidateError;

    struct C<'a> {
        authzid: &'a str,
        token: &'a str,
        result: Result<(), OAuthBearerValidateError<'a>>,
    }

    impl SessionCallback for C<'_> {
        fn callback(
            &self,
            _session_data: &SessionData,
            context: &Context,
            request: &mut Request,
        ) -> Result<(), SessionError> {
            if request.is::<OAuthBearerValidate>() {
                assert_eq!(context.get_ref::<AuthzId>(), Some(self.authzid));
                assert_eq!(context.get_ref::<OAuthBearerToken>(), Some(self.token));

                request.satisfy::<OAuthBearerValidate>(&self.result)?;
            }

            Ok(())
        }
    }

    impl Default for C<'static> {
        fn default() -> Self {
            Self {
                authzid: "username@host.tld",
                token: "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg",
                result: Ok(()),
            }
        }
    }

    fn prepare_session(callback: C<'static>) -> Session {
        let _authid = "username@host.tld";
        let _token = "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg";
        let config = test::server_config(callback);
        test::server_session(config, &super::super::mechinfo::OAUTHBEARER)
    }

    #[test]
    fn test_successful() {
        let mut session = prepare_session(C::default());
        let mut out = Cursor::new(Vec::new());

        let data = b"n,a=username@host.tld,\x01auth=ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg\x01\x01";
        let state = session.step(Some(data), &mut out).unwrap();

        assert!(state.is_finished());
        assert!(!state.has_sent_message());
    }

    #[test]
    fn test_errored() {
        let err = OAuthBearerValidateError {
            status: "invalid_token",
            scope: None,
            openid_config: None
        };
        let result = Err(err.clone());
        let mut session = prepare_session(C {
            result,
            ..Default::default()
        });
        let mut out = Cursor::new(Vec::<u8>::new());

        let data = b"n,a=username@host.tld,\x01auth=ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg\x01\x01";
        let state = session.step(Some(data), &mut out).unwrap();

        let data = out.into_inner();

        assert!(state.is_running());
        assert!(state.has_sent_message());
        let err_parsed: OAuthBearerValidateError = serde_json::from_slice(&data).unwrap();
        assert_eq!(err, err_parsed);
    }
}
