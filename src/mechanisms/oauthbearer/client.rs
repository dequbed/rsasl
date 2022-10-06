use crate::context::EmptyProvider;
use crate::error::SessionError;
use crate::mechanism::{Authentication, MechanismData, State};
use crate::mechanisms::oauthbearer::properties::{Error, OAuthBearerErrored};
use crate::property::{AuthzId, OAuthBearerKV, OAuthBearerToken};
use crate::session::MessageSent;
use crate::vectored_io::VectoredWriter;
use alloc::io::Write;

#[derive(Debug, Default, Clone)]
pub struct OAuthBearer {
    state: OAuthBearerState,
}

#[derive(Debug, Clone)]
enum OAuthBearerState {
    Initial,
    WaitingServerResponse,
    Done,
}

impl Default for OAuthBearerState {
    fn default() -> Self {
        Self::Initial
    }
}

impl Authentication for OAuthBearer {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<State, SessionError> {
        match self.state {
            OAuthBearerState::Initial => {
                writer.write_all(b"n,")?;
                session.maybe_need_with::<AuthzId, _, _>(&EmptyProvider, |authzid| {
                    writer.write_all(b"a=")?;
                    writer.write_all(authzid.as_bytes())?;
                    Ok(())
                })?;
                writer.write_all(b",")?;

                session.maybe_need_with::<OAuthBearerKV, _, _>(&EmptyProvider, |kvpairs| {
                    for (k, v) in kvpairs {
                        let data = [b"\x01", k.as_bytes(), b"=", v.as_bytes()];
                        let mut vecw = VectoredWriter::new(data);
                        vecw.write_all_vectored(&mut *writer)?;
                    }
                    Ok(())
                })?;

                session.need_with::<OAuthBearerToken, _, _>(&EmptyProvider, |token| {
                    let data = [b"\x01auth=Bearer ", token.as_bytes(), b"\x01\x01"];
                    let mut vecw = VectoredWriter::new(data);
                    vecw.write_all_vectored(writer)?;
                    Ok(())
                })?;

                self.state = OAuthBearerState::WaitingServerResponse;

                Ok(State::Running)
            }
            OAuthBearerState::WaitingServerResponse => {
                // whatever happens, afterwards this mechanisms won't be stepable again, so we
                // can set to done right here too
                self.state = OAuthBearerState::Done;

                let input = input.unwrap_or(&[]);
                // Empty case is specifically *no error message*. So yeah, that's finished then?
                // Most protocols will indicate success via the protocol immediately so this
                // should only be hit if we get protocol handlers being cautious and calling step in
                // that case too. Which, granted, is a good thing! We want that!
                if input.is_empty() {
                    return Ok(State::Finished(MessageSent::No));
                }

                let error = serde_json::from_slice(input).map_err(Error::Serde)?;

                // If the user callback *doesn't*, we must error, so '?' is correct.
                session.action::<OAuthBearerErrored>(&EmptyProvider, &error)?;
                Ok(State::Finished(MessageSent::Yes))
            }
            OAuthBearerState::Done => Err(SessionError::MechanismDone),
        }
    }
}
