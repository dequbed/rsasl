use crate::alloc::format;
use crate::alloc::{boxed::Box, string::String, vec::Vec};
use crate::context::{Demand, DemandReply, Provider};
use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::mechanism::Authentication;
use crate::mechanisms::scram::client::{ProtocolError, SCRAMError};
use crate::mechanisms::scram::parser::{
    ClientFinal, ClientFirstMessage, GS2CBindFlag, ServerErrorValue, ServerFinal, ServerFirst,
};
use crate::mechanisms::scram::properties::ScramStoredPassword;
use crate::mechanisms::scram::tools::{compute_signatures, generate_nonce, DOutput};
use crate::property::{AuthId, AuthzId};
use crate::session::{MechanismData, MessageSent, State};
use crate::vectored_io::VectoredWriter;
use base64::Engine;
use core::marker::PhantomData;
use core2::io::Write;
use digest::crypto_common::BlockSizeUser;
use digest::generic_array::GenericArray;
use digest::{Digest, FixedOutput, OutputSizeUser};
use hmac::SimpleHmac;
use rand::{thread_rng, Rng, RngCore};
use thiserror::Error;

#[allow(dead_code)]
trait ScramConfig {
    type DIGEST: Digest + BlockSizeUser;
    const ALGORITHM_NAME: &'static str;

    const NONCE_LEN: usize;

    const DEFAULT_SALT_LEN: usize = 32;
    const DEFAULT_ITERATIONS: u32 = 2u32.pow(14);

    const ABORT_IMMEDIATELY: bool = false;
}

const DEFAULT_ITERATIONS: &[u8] = b"16384"; // 2u32.pow(14) TODO check if still reasonable
const DEFAULT_SALT_LEN: usize = 32;

#[cfg(feature = "scram-sha-1")]
pub type ScramSha1Server<const N: usize> = ScramServer<sha1::Sha1, N>;
#[cfg(feature = "scram-sha-2")]
pub type ScramSha256Server<const N: usize> = ScramServer<sha2::Sha256, N>;
#[cfg(feature = "scram-sha-2")]
pub type ScramSha512Server<const N: usize> = ScramServer<sha2::Sha512, N>;

#[derive(Debug, Error)]
pub enum ScramServerError {
    #[error("provided password hash is wrong size for selected algorithm")]
    PasswordHashInvalid,

    #[error("channel bindings are supported by both sides but were not used")]
    ChannelBindingsNotUsed,
}
impl MechanismError for ScramServerError {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CBSupport {
    /// Server doesn't support CB
    No,
    /// Server *does* support CB
    Yes,
}

pub struct ScramServer<D: Digest + BlockSizeUser + FixedOutput, const N: usize> {
    state: Option<ScramServerState<D, N>>,
}
impl<D: Digest + BlockSizeUser + FixedOutput, const N: usize> ScramServer<D, N> {
    pub const fn new(can_cb: bool) -> Self {
        let plus = if can_cb {
            CBSupport::Yes
        } else {
            CBSupport::No
        };
        Self {
            state: Some(ScramServerState::WaitingClientFirst(ScramState::new(plus))),
        }
    }

    pub const fn new_plus() -> Self {
        let plus = CBSupport::Yes;
        Self {
            state: Some(ScramServerState::WaitingClientFirst(ScramState::new(plus))),
        }
    }
}

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

pub struct WaitingClientFirst<const N: usize> {
    plus: CBSupport,
    nonce: PhantomData<&'static [u8; N]>,
}

impl<const N: usize> WaitingClientFirst<N> {
    const fn new(plus: CBSupport) -> Self {
        Self {
            plus,
            nonce: PhantomData,
        }
    }

    fn handle_client_first<D: Digest + BlockSizeUser + FixedOutput>(
        self,
        rng: &mut impl Rng,
        session_data: &mut MechanismData,
        client_first: &[u8],
        writer: impl Write,
        written: &mut usize,
    ) -> Result<WaitingClientFinal<D, N>, SessionError> {
        // Step 1: (try to) parse the client message received.
        let client_first @ ClientFirstMessage {
            cbflag,
            authzid, // FIXME: Save authzid
            username: authid,
            nonce: client_nonce,
        } = ClientFirstMessage::parse(client_first).map_err(SCRAMError::ParseError)?;

        // AuthMessage we need to validate the user:
        // client-first-message-bare + "," + server-first-message + "," + client-final-message-without-proof

        // TODO: Only store this if we're a -PLUS
        let mut gs2_header = client_first.build_gs2_header_vec();

        // FIXME: Escape Username from SCRAM format to whatever
        // TODO: This must at this stage provide so much more info <.<
        let provider = Prov { authid, authzid };

        match cbflag {
            // TODO: check if this is a protocol downgrade
            GS2CBindFlag::SupportedNotUsed => {
                if self.plus == CBSupport::Yes {
                    return Err(SessionError::MechanismError(Box::new(
                        ScramServerError::ChannelBindingsNotUsed,
                    )));
                }
            }
            GS2CBindFlag::NotSupported => {}
            GS2CBindFlag::Used(name) => session_data.need_cb_data(name, provider, |cbdata| {
                gs2_header.extend_from_slice(cbdata);
                Ok(())
            })?,
        };

        let params = session_data.maybe_need_with::<ScramStoredPassword, _, _>(
            &provider,
            |ScramStoredPassword {
                 iterations,
                 salt,
                 stored_key,
                 server_key,
             }| {
                // First, check if the given values are even possible; we know the digest in
                // use, we exactly know its output size
                let hmac_len = <SimpleHmac<D> as OutputSizeUser>::output_size();
                let hash_len = <D as Digest>::output_size();
                if stored_key.len() != hash_len || server_key.len() != hmac_len {
                    return Err(SessionError::MechanismError(Box::new(
                        ScramServerError::PasswordHashInvalid,
                    )));
                }

                Ok((
                    format!("{iterations}"),
                    base64::engine::general_purpose::STANDARD.encode(salt),
                    GenericArray::clone_from_slice(stored_key),
                    GenericArray::clone_from_slice(server_key),
                ))
            },
        )?;

        let server_nonce: [u8; N] = generate_nonce(rng);

        if let Some((iterations, salt, stored_key, server_key)) = params {
            let msg = ServerFirst::new(
                client_nonce,
                &server_nonce,
                salt.as_bytes(),
                iterations.as_bytes(),
            );
            let mut vecw = VectoredWriter::new(msg.as_ioslices());
            *written = vecw.write_all_vectored(writer)?;

            Ok(WaitingClientFinal::new(
                client_nonce.into(),
                server_nonce,
                gs2_header,
                authid.to_string(),
                authzid.map(ToString::to_string),
                salt,
                iterations,
                stored_key,
                server_key,
            ))
        } else {
            let mut salt = [0u8; DEFAULT_SALT_LEN];
            thread_rng().fill_bytes(&mut salt);
            let salt = base64::engine::general_purpose::STANDARD.encode(salt);

            let msg = ServerFirst::new(
                client_nonce,
                &server_nonce,
                salt.as_bytes(),
                DEFAULT_ITERATIONS,
            );
            let mut vecw = VectoredWriter::new(msg.as_ioslices());
            *written = vecw.write_all_vectored(writer)?;

            Ok(WaitingClientFinal::bad_user())
        }
    }
}

pub struct WaitingClientFinal<D: Digest + BlockSizeUser + FixedOutput, const N: usize> {
    data: Option<FinalInner<D, N>>,
}
struct FinalInner<D: Digest + BlockSizeUser + FixedOutput, const N: usize> {
    client_nonce: Vec<u8>,
    server_nonce: [u8; N],
    gs2_header: Vec<u8>,
    username: String,
    authzid: Option<String>,
    salt: String,
    iterations: String,
    stored_key: GenericArray<u8, D::OutputSize>,
    server_key: DOutput<D>,
}
impl<D: Digest + BlockSizeUser + FixedOutput, const N: usize> WaitingClientFinal<D, N> {
    // There really isn't a good way of cutting down on the number of args and they are *pretty*
    // self-explanatory.
    #[allow(clippy::too_many_arguments)]
    fn new(
        client_nonce: Vec<u8>,
        server_nonce: [u8; N],
        gs2_header: Vec<u8>,
        username: String,
        authzid: Option<String>,
        salt: String,
        iterations: String,
        stored_key: GenericArray<u8, D::OutputSize>,
        server_key: DOutput<D>,
    ) -> Self {
        Self {
            data: Some(FinalInner {
                client_nonce,
                server_nonce,
                gs2_header,
                username,
                authzid,
                salt,
                iterations,
                stored_key,
                server_key,
            }),
        }
    }

    const fn bad_user() -> Self {
        Self { data: None }
    }

    fn handle_client_final(
        self,
        client_final: &[u8],
        session_data: &mut MechanismData,
        writer: impl Write,
        written: &mut usize,
    ) -> Result<(), SessionError> {
        let ClientFinal {
            channel_binding,
            nonce,
            proof,
        } = ClientFinal::parse(client_final).map_err(SCRAMError::ParseError)?;

        let msg = if let Some(FinalInner {
            client_nonce,
            server_nonce,
            gs2_header,
            username,
            authzid,
            salt,
            iterations,
            stored_key,
            server_key,
        }) = self.data
        {
            let cb = base64::engine::general_purpose::STANDARD
                .decode(channel_binding)
                .map_err(|_| SCRAMError::Protocol(ProtocolError::Base64Decode))?;

            if gs2_header[..] != cb[..] {
                ServerFinal::Error(ServerErrorValue::ChannelBindingsDontMatch)
            } else if let Some(remainder) = nonce.strip_prefix(&client_nonce[..]) {
                if remainder == server_nonce
                    && proof.len() <= (<SimpleHmac<D> as OutputSizeUser>::output_size() * 4 / 3) + 3
                {
                    let mut proof_decoded = DOutput::<D>::default();
                    base64::engine::general_purpose::STANDARD
                        .decode_slice(proof, &mut proof_decoded)
                        .map_err(|_| SCRAMError::Protocol(ProtocolError::Base64Decode))?;

                    let mut client_signature = DOutput::<D>::default();
                    let mut server_signature = DOutput::<D>::default();

                    compute_signatures::<D>(
                        &stored_key,
                        &server_key,
                        &username,
                        &client_nonce,
                        &server_nonce,
                        salt.as_bytes(),
                        iterations.as_bytes(),
                        channel_binding,
                        &mut client_signature,
                        &mut server_signature,
                    );

                    // Calculate the client_key by XORing the provided proof with the
                    // calculated client signature
                    let client_key = DOutput::<D>::from_exact_iter(
                        proof_decoded
                            .into_iter()
                            .zip(client_signature)
                            .map(|(x, y)| x ^ y),
                    )
                    .expect("XOR of two same-sized arrays was not of that size?");

                    let calculated_stored_key = D::digest(client_key);

                    if stored_key == calculated_stored_key {
                        let encoded =
                            base64::engine::general_purpose::STANDARD.encode(server_signature);
                        let msg = ServerFinal::Verifier(encoded.as_bytes());
                        let mut vecw = VectoredWriter::new(msg.to_ioslices());
                        *written = vecw.write_all_vectored(writer)?;

                        let prov = Prov {
                            authid: username.as_str(),
                            authzid: authzid.as_deref(),
                        };
                        session_data.validate(&prov)?;

                        return Ok(());
                    }
                    ServerFinal::Error(ServerErrorValue::InvalidProof)
                } else {
                    ServerFinal::Error(ServerErrorValue::InvalidProof)
                }
            } else {
                ServerFinal::Error(ServerErrorValue::InvalidProof)
            }
        } else {
            ServerFinal::Error(ServerErrorValue::UnknownUser)
        };

        let mut vecw = VectoredWriter::new(msg.to_ioslices());
        *written = vecw.write_all_vectored(writer)?;

        Ok(())
    }
}

struct ScramState<S> {
    state: S,
}
impl<const N: usize> ScramState<WaitingClientFirst<N>> {
    const fn new(plus: CBSupport) -> Self {
        Self {
            state: WaitingClientFirst::new(plus),
        }
    }

    fn step<D: Digest + BlockSizeUser + FixedOutput>(
        self,
        rng: &mut impl Rng,
        session_data: &mut MechanismData,
        input: &[u8],
        writer: impl Write,
        written: &mut usize,
    ) -> Result<ScramState<WaitingClientFinal<D, N>>, SessionError> {
        let state = self
            .state
            .handle_client_first(rng, session_data, input, writer, written)?;
        Ok(ScramState { state })
    }
}
impl<D: Digest + BlockSizeUser + FixedOutput, const N: usize> ScramState<WaitingClientFinal<D, N>> {
    fn step(
        self,
        input: &[u8],
        session_data: &mut MechanismData,
        writer: impl Write,
        written: &mut usize,
    ) -> Result<ScramState<()>, SessionError> {
        self.state
            .handle_client_final(input, session_data, writer, written)?;
        Ok(ScramState { state: () })
    }
}

enum ScramServerState<D: Digest + BlockSizeUser + FixedOutput, const N: usize> {
    WaitingClientFirst(ScramState<WaitingClientFirst<N>>),
    WaitingClientFinal(ScramState<WaitingClientFinal<D, N>>),
    Finished(ScramState<()>),
}

impl<D: Digest + BlockSizeUser + FixedOutput, const N: usize> Authentication for ScramServer<D, N> {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<State, SessionError> {
        use ScramServerState::{Finished, WaitingClientFinal, WaitingClientFirst};
        match self.state.take() {
            Some(WaitingClientFirst(state)) => {
                let client_first = input.ok_or(SessionError::InputDataRequired)?;

                let mut rng = rand::thread_rng();
                let mut written = 0;
                let new_state =
                    state.step(&mut rng, session, client_first, writer, &mut written)?;
                self.state = Some(WaitingClientFinal(new_state));
                Ok(State::Running)
            }
            Some(WaitingClientFinal(state)) => {
                let client_final = input.ok_or(SessionError::InputDataRequired)?;
                let mut written = 0;
                let new_state = state.step(client_final, session, writer, &mut written)?;
                self.state = Some(Finished(new_state));
                Ok(State::Finished(MessageSent::Yes))
            }
            Some(Finished(_state)) => Err(SessionError::MechanismDone),

            None => panic!("SCRAM server state machine in invalid state"),
        }
    }
}
