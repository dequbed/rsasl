use std::io::Write;
use std::marker::PhantomData;
use digest::crypto_common::BlockSizeUser;
use digest::Digest;
use digest::generic_array::GenericArray;
use rand::{Rng, RngCore, thread_rng};
use stringprep::saslprep;
use crate::Authentication;
use crate::callback::CallbackError;
use crate::error::SessionError;
use crate::mechanisms::scram::client::SCRAMError;
use crate::mechanisms::scram::parser::{ClientFinal, ClientFirstMessage, ServerErrorValue, ServerFinal, ServerFirst};
use crate::mechanisms::scram::properties::{ScramPassParams, ScramSaltedPassword, ScramSaltedPasswordQuery};
use crate::mechanisms::scram::tools::{DOutput, find_proofs, generate_nonce};
use crate::session::{MechanismData, StepResult};
use crate::session::Step::{Done, NeedsMore};
use crate::vectored_io::VectoredWriter;


const DEFAULT_ITERATIONS: u32 = 2u32.pow(14); // 16384, TODO check if still reasonable
const DEFAULT_SALT_LEN: usize = 32;

pub type ScramSha1Server<const N: usize> = ScramServer<sha1::Sha1, N>;
pub type ScramSha256Server<const N: usize> = ScramServer<sha2::Sha256, N>;
pub type ScramSha512Server<const N: usize> = ScramServer<sha2::Sha512, N>;

pub struct ScramServer<D: Digest + BlockSizeUser, const N: usize> {
    plus: bool,
    state: Option<ScramServerState<D, N>>,
}
impl<D: Digest + BlockSizeUser, const N: usize> ScramServer<D, N> {
    pub fn new() -> Self {
        Self {
            plus: false,
            state: Some(ScramServerState::WaitingClientFirst(State::new()))
        }
    }

    pub fn new_plus() -> Self {
        Self {
            plus: true,
            state: Some(ScramServerState::WaitingClientFirst(State::new()))
        }
    }
}

pub struct WaitingClientFirst<const N: usize> {
    nonce: PhantomData<&'static [u8; N]>
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
            cbflag: _,
            authzid: _, // FIXME: Save authzid
            username,
            nonce: client_nonce
        } = ClientFirstMessage::parse(client_first).map_err(SCRAMError::ParseError)?;

        // FIXME: Escape Username from SCRAM format to whatever

        // Retrieve the password for the given user via callback.
        // If the callback doesn't return a password (usually because the user does not exist) we
        // proceed with the authentication exchange with randomly generated data, since SCRAM
        // only indicates failure like that in the last step.
        let (ScramPassParams {
                iterations,
                salt,
            },
            password
        ) = self.get_salted_pw(session_data, username)?
            //^ do a callback to get values
            .map(|ScramSaltedPassword { params, password }| (params, Some(password)))
            //^ Make the value Option<(Params, Option<Password>)> so we can work with it
            .unwrap_or_else(|| (self.gen_rand_pw_params(), None));
            //^ Generate new random values if no password was returned


        let server_nonce: [u8; N] = generate_nonce(rng);

        let it_bytes = iterations.to_be_bytes();
        let msg = ServerFirst::new(
            &client_nonce,
            &server_nonce,
            &salt,
            &it_bytes,
        );
        let mut vecw = VectoredWriter::new(msg.to_ioslices());
        *written = vecw.write_all_vectored(writer)?;

        let mut common_nonce = Vec::with_capacity(client_nonce.len() + server_nonce.len());
        common_nonce.extend_from_slice(&client_nonce);
        common_nonce.extend_from_slice(&server_nonce);

        if let Some(salted_password) = password {
            let gs2header = client_first.build_gs2_header_vec();
            let gs2headerb64 = base64::encode(gs2header);

            let (proof, signature) = find_proofs::<D>(
                username,
                client_nonce,
                msg,
                &gs2headerb64,
                &GenericArray::from_slice(&salted_password),
            );
            Ok(WaitingClientFinal::new(common_nonce, proof, signature))
        } else {
            Ok(WaitingClientFinal::bad_user(common_nonce))
        }
    }

    fn get_salted_pw(&self, session_data: &mut MechanismData, username: &str)
        -> Result<Option<ScramSaltedPassword>, SessionError>
    {
        let username = saslprep(username).expect("SASLprep failed").to_string();
        match session_data.need::<ScramSaltedPasswordQuery>(username) {
            Ok(answer) => Ok(Some(answer)),
            Err(CallbackError::NoCallback | CallbackError::NoAnswer) => {
                Ok(None)
            },
            Err(e) => Err(e.into())
        }
    }

    fn gen_rand_pw_params(&self) -> ScramPassParams {
        let mut salt = [0u8; DEFAULT_SALT_LEN];
        thread_rng().fill_bytes(&mut salt);

        ScramPassParams {
            iterations: DEFAULT_ITERATIONS,
            salt: salt.into(),
        }
    }
}

pub struct WaitingClientFinal<D: Digest + BlockSizeUser>{
    nonce: Vec<u8>,
    data: Option<FinalInner<D>>
}
struct FinalInner<D: Digest + BlockSizeUser> {
    proof: DOutput<D>,
    signature: DOutput<D>,
}
impl<D: Digest + BlockSizeUser> WaitingClientFinal<D> {
    pub fn new(nonce: Vec<u8>, proof: DOutput<D>, signature: DOutput<D>) -> Self {
        Self { nonce, data: Some(FinalInner { proof, signature }) }
    }
    pub fn bad_user(nonce: Vec<u8>) -> Self {
        Self { nonce, data: None }
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

        let msg = if !self.verify_channel_bindings(channel_binding) {
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
                        *written = vecw.write_all_vectored(writer)?;
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

    pub fn verify_channel_bindings(&self, _channel_binding: &[u8]) -> bool {
        todo!()
    }
}

pub enum Outcome {
    Failed,
    Successful {
        username: (),
    }
}


struct State<S> {
    state: S,
}
impl<const N: usize> State<WaitingClientFirst<N>> {
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
    ) -> Result<State<WaitingClientFinal<D>>, SessionError> {
        let state = self.state.handle_client_first(
            rng,
            session_data,
            input,
            writer,
            written
        )?;
        Ok(State { state })
    }
}
impl<D: Digest + BlockSizeUser> State<WaitingClientFinal<D>> {
    pub fn step(
        self,
        input: &[u8],
        writer: impl Write,
        written: &mut usize,
    ) -> Result<State<Outcome>, SessionError> {
        let state = self.state.handle_client_final(input, writer, written)?;
        Ok(State { state })
    }
}

enum ScramServerState<D: Digest + BlockSizeUser, const N: usize> {
    WaitingClientFirst(State<WaitingClientFirst<N>>),
    WaitingClientFinal(State<WaitingClientFinal<D>>),
    Finished(State<Outcome>)
}

impl<D: Digest + BlockSizeUser, const N: usize> Authentication for ScramServer<D, N> {
    fn step(&mut self, session: &mut MechanismData, input: Option<&[u8]>, writer: &mut dyn Write) -> StepResult {
        use ScramServerState::*;
        match self.state.take() {
            Some(WaitingClientFirst(state)) => {
                let client_first = input.ok_or(SessionError::InputDataRequired)?;

                let mut rng = rand::thread_rng();
                let mut written = 0;
                let new_state = state.step(
                    &mut rng,
                    session,
                    client_first,
                    writer,
                    &mut written
                )?;
                self.state = Some(WaitingClientFinal(new_state));
                Ok(NeedsMore(Some(written)))
            },
            Some(WaitingClientFinal(state)) => {
                let client_final = input.ok_or(SessionError::InputDataRequired)?;
                let mut written = 0;
                let new_state = state.step(
                    client_final,
                    writer,
                    &mut written
                )?;
                self.state = Some(Finished(new_state));
                Ok(Done(Some(written)))
            },
            Some(Finished(_state)) => {
                Err(SessionError::MechanismDone)
            },

            None => panic!("SCRAM server state machine in invalid state"),
        }
    }
}
