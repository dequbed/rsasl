use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::mechanisms::scram::client::{ProtocolError, SCRAMError};
use crate::mechanisms::scram::parser::{ClientFinal, ClientFirstMessage, GS2CBindFlag, ServerErrorValue, ServerFinal, ServerFirst};
use crate::mechanisms::scram::tools::{find_proofs, generate_nonce, DOutput};
use crate::session::{MechanismData, State};
use crate::vectored_io::VectoredWriter;
use digest::crypto_common::BlockSizeUser;
use digest::generic_array::GenericArray;
use digest::{Digest, OutputSizeUser};
use hmac::SimpleHmac;
use rand::{thread_rng, Rng, RngCore};
use std::io::Write;
use std::marker::PhantomData;
use thiserror::Error;

use crate::context::{Demand, DemandReply, Provider};
use crate::mechanism::Authentication;
use crate::mechanisms::scram::properties::{HashIterations, PasswordHash, Salt};
use crate::property::{AuthId, AuthzId};

const DEFAULT_ITERATIONS: u32 = 2u32.pow(14); // 16384, TODO check if still reasonable
const DEFAULT_SALT_LEN: usize = 32;

#[cfg(feature = "scram-sha-1")]
pub type ScramSha1Server<const N: usize> = ScramServer<sha1::Sha1, N>;
#[cfg(feature = "scram-sha-2")]
pub type ScramSha256Server<const N: usize> = ScramServer<sha2::Sha256, N>;
// #[cfg(feature = "scram-sha-2")]
// pub type ScramSha512Server<const N: usize> = ScramServer<sha2::Sha512, N>;

#[derive(Debug, Error)]
pub enum ScramServerError {
    #[error("provided password hash is wrong size for selected algorithm")]
    PasswordHashInvalid,
}
impl MechanismError for ScramServerError {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}

pub struct ScramServer<D: Digest + BlockSizeUser, const N: usize> {
    plus: bool,
    state: Option<ScramServerState<D, N>>,
}
impl<D: Digest + BlockSizeUser, const N: usize> ScramServer<D, N> {
    pub fn new() -> Self {
        Self {
            plus: false,
            state: Some(ScramServerState::WaitingClientFirst(ScramState::new())),
        }
    }

    pub fn new_plus() -> Self {
        Self {
            plus: true,
            state: Some(ScramServerState::WaitingClientFirst(ScramState::new())),
        }
    }
}

pub struct WaitingClientFirst<const N: usize> {
    nonce: PhantomData<&'static [u8; N]>,
}

impl<const N: usize> WaitingClientFirst<N> {
    pub fn new() -> Self {
        Self { nonce: PhantomData }
    }

    pub fn handle_client_first<D: Digest + BlockSizeUser>(
        self,
        rng: &mut impl Rng,
        session_data: &mut MechanismData,
        client_first: &[u8],
        writer: impl Write,
        written: &mut usize,
    ) -> Result<WaitingClientFinal<D>, SessionError> {
        // Step 1: (try to) parse the client message received.
        let client_first @ ClientFirstMessage {
            cbflag,
            authzid, // FIXME: Save authzid
            username: authid,
            nonce: client_nonce,
        } = ClientFirstMessage::parse(client_first).map_err(SCRAMError::ParseError)?;

        // FIXME: Escape Username from SCRAM format to whatever
        #[derive(Copy, Clone)]
        struct Prov<'a> {
            authid: &'a str,
            authzid: Option<&'a str>,
        }
        impl<'a> Provider<'a> for Prov<'a> {
            fn provide(&self, req: &mut Demand<'a>) -> DemandReply<()> {
                req.provide_ref::<AuthId>(self.authid)?;
                if let Some(authzid) = self.authzid {
                    req.provide_ref::<AuthzId>(authzid)?;
                }
                req.done()
            }
        }

        let provider = Prov { authid, authzid };
        let mut gs2_header = client_first.build_gs2_header_vec();

        match cbflag {
            // TODO: check if this is a likely protocol downgrade
            GS2CBindFlag::SupportedNotUsed => {},
            GS2CBindFlag::NotSupported => {},
            GS2CBindFlag::Used(name) => session_data.need_cb_data(name, provider, |cbdata| {
                gs2_header.extend_from_slice(cbdata);
                Ok(())
            })?,
        };

        let password: Option<GenericArray<u8, D::OutputSize>>;

        // Retrieve the password for the given user via callback.
        // If the callback doesn't return a password (usually because the user does not exist) we
        // proceed with the authentication exchange with randomly generated data, since SCRAM
        // only indicates failure like that in the last step.
        password =
            session_data.maybe_need_with::<PasswordHash, _, _>(&provider, |password| {
                if password.len() != <SimpleHmac<D> as OutputSizeUser>::output_size() {
                    return Err(SessionError::MechanismError(Box::new(
                        ScramServerError::PasswordHashInvalid,
                    )));
                }
                Ok(GenericArray::clone_from_slice(password))
            })?;

        let (iterations, salt) = if password.is_some() {
            let iterations = session_data
                .need_with::<HashIterations, _, _>(&provider, |iterations| Ok(*iterations))?;
            let salt = session_data
                .need_with::<Salt, _, _>(&provider, |salt| Ok(base64::encode(salt)))?;
            (iterations, salt)
        } else {
            self.gen_rand_pw_params()
        };

        let server_nonce: [u8; N] = generate_nonce(rng);

        let it_bytes = format!("{}", iterations);
        let msg = ServerFirst::new(
            &client_nonce,
            &server_nonce,
            salt.as_bytes(),
            it_bytes.as_bytes(),
        );
        let mut vecw = VectoredWriter::new(msg.to_ioslices());
        *written = vecw.write_all_vectored(writer)?;

        let mut common_nonce = Vec::with_capacity(client_nonce.len() + server_nonce.len());
        common_nonce.extend_from_slice(&client_nonce);
        common_nonce.extend_from_slice(&server_nonce);

        if let Some(salted_password) = password {
            let gs2_header_b64 = base64::encode(&gs2_header[..]);

            let (proof, signature) = find_proofs::<D>(
                authid,
                client_nonce,
                msg,
                &gs2_header_b64,
                &GenericArray::from_slice(&salted_password),
            );
            Ok(WaitingClientFinal::new(common_nonce, gs2_header, proof, signature))
        } else {
            Ok(WaitingClientFinal::bad_user(common_nonce, gs2_header))
        }
    }

    fn gen_rand_pw_params(&self) -> (u32, String) {
        let mut salt = [0u8; DEFAULT_SALT_LEN];
        thread_rng().fill_bytes(&mut salt);

        (DEFAULT_ITERATIONS, base64::encode(salt))
    }
}

pub struct WaitingClientFinal<D: Digest + BlockSizeUser> {
    nonce: Vec<u8>,
    gs2_header: Vec<u8>,
    data: Option<FinalInner<D>>,
}
struct FinalInner<D: Digest + BlockSizeUser> {
    proof: DOutput<D>,
    signature: DOutput<D>,
}
impl<D: Digest + BlockSizeUser> WaitingClientFinal<D> {
    pub fn new(nonce: Vec<u8>, gs2_header: Vec<u8>, proof: DOutput<D>, signature: DOutput<D>)
        -> Self
    {
        Self {
            nonce,
            gs2_header,
            data: Some(FinalInner { proof, signature }),
        }
    }
    pub fn bad_user(nonce: Vec<u8>, gs2_header: Vec<u8>) -> Self {
        Self { nonce, gs2_header, data: None }
    }

    pub fn handle_client_final(
        self,
        client_final: &[u8],
        writer: impl Write,
        written: &mut usize,
    ) -> Result<Outcome, SessionError> {
        let ClientFinal {
            channel_binding,
            nonce,
            proof,
        } = ClientFinal::parse(client_final).map_err(SCRAMError::ParseError)?;

        let outcome = Outcome::Failed;

        let cb = base64::decode(channel_binding)
            .map_err(|_| SCRAMError::Protocol(ProtocolError::Base64Decode))?;


        let msg = if !self.verify_channel_bindings(&cb) {
            ServerFinal::Error(ServerErrorValue::ChannelBindingsDontMatch)
        } else {
            if nonce != self.nonce {
                ServerFinal::Error(ServerErrorValue::InvalidProof)
            } else {
                if let Some(data) = self.data {
                    if proof != data.proof.as_slice() {
                        ServerFinal::Error(ServerErrorValue::InvalidProof)
                    } else {
                        let msg = ServerFinal::Verifier(data.signature.as_slice());
                        let mut vecw = VectoredWriter::new(msg.to_ioslices());
                        * written = vecw.write_all_vectored(writer)?;
                        // FIXME: We need to validate the authzid/authid combo first!
                        return Ok(Outcome::Successful { username: () });
                    }
                } else {
                    ServerFinal::Error(ServerErrorValue::UnknownUser)
                }
            }
        };

        let mut vecw = VectoredWriter::new(msg.to_ioslices());
        *written = vecw.write_all_vectored(writer)?;

        Ok(outcome)
    }

    pub fn verify_channel_bindings(&self, channel_binding: &[u8]) -> bool {
        &self.gs2_header[..] == channel_binding
    }
}

pub enum Outcome {
    Failed,
    Successful { username: () },
}

struct ScramState<S> {
    state: S,
}
impl<const N: usize> ScramState<WaitingClientFirst<N>> {
    pub fn new() -> Self {
        Self {
            state: WaitingClientFirst::new(),
        }
    }

    pub fn step<D: Digest + BlockSizeUser>(
        self,
        rng: &mut impl Rng,
        session_data: &mut MechanismData,
        input: &[u8],
        writer: impl Write,
        written: &mut usize,
    ) -> Result<ScramState<WaitingClientFinal<D>>, SessionError> {
        let state = self
            .state
            .handle_client_first(rng, session_data, input, writer, written)?;
        Ok(ScramState { state })
    }
}
impl<D: Digest + BlockSizeUser> ScramState<WaitingClientFinal<D>> {
    pub fn step(
        self,
        input: &[u8],
        writer: impl Write,
        written: &mut usize,
    ) -> Result<ScramState<Outcome>, SessionError> {
        let state = self.state.handle_client_final(input, writer, written)?;
        Ok(ScramState { state })
    }
}

enum ScramServerState<D: Digest + BlockSizeUser, const N: usize> {
    WaitingClientFirst(ScramState<WaitingClientFirst<N>>),
    WaitingClientFinal(ScramState<WaitingClientFinal<D>>),
    Finished(ScramState<Outcome>),
}

impl<D: Digest + BlockSizeUser, const N: usize> Authentication for ScramServer<D, N> {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<(State, Option<usize>), SessionError> {
        use ScramServerState::*;
        match self.state.take() {
            Some(WaitingClientFirst(state)) => {
                let client_first = input.ok_or(SessionError::InputDataRequired)?;

                let mut rng = rand::thread_rng();
                let mut written = 0;
                let new_state =
                    state.step(&mut rng, session, client_first, writer, &mut written)?;
                self.state = Some(WaitingClientFinal(new_state));
                Ok((State::Running, Some(written)))
            }
            Some(WaitingClientFinal(state)) => {
                let client_final = input.ok_or(SessionError::InputDataRequired)?;
                let mut written = 0;
                let new_state = state.step(client_final, writer, &mut written)?;
                self.state = Some(Finished(new_state));
                Ok((State::Finished, Some(written)))
            }
            Some(Finished(_state)) => Err(SessionError::MechanismDone),

            None => panic!("SCRAM server state machine in invalid state"),
        }
    }
}
