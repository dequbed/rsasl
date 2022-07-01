use std::fmt::{Display, Formatter};
use std::io::Write;
use std::marker::PhantomData;




use digest::crypto_common::BlockSizeUser;
use digest::Digest;
use digest::generic_array::GenericArray;

use rand::Rng;

use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::mechanisms::scram::parser::{
    ClientFinal, ClientFirstMessage,
    GS2CBindFlag, SaslName, ServerErrorValue, ServerFinal, ServerFirst,
};
use crate::mechanisms::scram::tools::{find_proofs, hash_password, DOutput, generate_nonce};
use crate::session::Step::NeedsMore;
use crate::session::{MechanismData, Step, StepResult};
use crate::vectored_io::VectoredWriter;
use crate::{Authentication};
use crate::mechanisms::common::properties::{Credentials, SimpleCredentials};

pub type ScramSha256Client<const N: usize> = ScramClient<sha2::Sha256, N>;
pub type ScramSha512Client<const N: usize> = ScramClient<sha2::Sha512, N>;
pub type ScramSha1Client<const N: usize> = ScramClient<sha1::Sha1, N>;

pub struct ScramClient<D: Digest + BlockSizeUser + Clone + Sync, const N: usize> {
    plus: bool,
    state: Option<ScramClientState<D, N>>,
}

impl<D: Digest + BlockSizeUser + Clone + Sync, const N: usize> ScramClient<D, N> {
    pub fn new() -> Self {
        Self {
            plus: false,
            state: Some(ScramClientState::Initial(State::new(None))),
        }
    }

    pub fn new_plus() -> Self {
        Self {
            plus: true,
            state: Some(ScramClientState::Initial(State::new(None))),
        }
    }
}

enum ScramClientState<D: Digest + BlockSizeUser, const N: usize> {
    Initial(State<StateClientFirst<N>>),
    ClientFirst(State<WaitingServerFirst<D, N>>, Vec<u8>),
    ServerFirst(State<WaitingServerFinal<D>>),
}

struct State<S> {
    cbdata: Option<(&'static str, Box<[u8]>)>,
    state: S,
}

impl<const N: usize> State<StateClientFirst<N>> {
    pub fn new(cbdata: Option<(&'static str, Box<[u8]>)>) -> Self {
        Self {
            cbdata,
            state: StateClientFirst::new(),
        }
    }

    pub fn step<D: Digest + BlockSizeUser + Clone + Sync>(
        self,
        rng: &mut impl Rng,
        authzid: Option<String>,
        username: String,
        writer: impl Write,
        written: &mut usize,
    ) -> Result<State<WaitingServerFirst<D, N>>, SessionError> {
        let cbflag = if let Some((name, _)) = self.cbdata.as_ref() {
            GS2CBindFlag::Used(name)
        } else {
            GS2CBindFlag::NotSupported
        };
        let state = self
            .state
            .send_client_first(rng, cbflag, authzid, username, writer, written)?;
        Ok(State {
            state,
            cbdata: self.cbdata,
        })
    }
}

impl<D: Digest + BlockSizeUser + Clone + Sync, const N: usize> State<WaitingServerFirst<D, N>> {
    pub fn step(
        self,
        password: &[u8],
        server_first: &[u8],
        writer: impl Write,
        written: &mut usize,
    ) -> Result<State<WaitingServerFinal<D>>, SessionError> {
        let cbdata = self.cbdata.map(|(_, b)| b);
        let state =
            self.state
                .handle_server_first(password, cbdata, server_first, writer, written)?;
        Ok(State {
            state,
            cbdata: None,
        })
    }
}

impl<D: Digest + BlockSizeUser> State<WaitingServerFinal<D>> {
    pub fn step(self, server_final: &[u8]) -> Result<(), SessionError> {
        match self.state.handle_server_final(server_final) {
            Ok(StateServerFinal { .. }) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

struct StateClientFirst<const N: usize> {
    nonce: PhantomData<&'static [u8; N]>,
    // Parameters Data required to send Client First Message
    //cb_flag: Option<&'static str>,
    //authzid: Option<&'static str>,
    //username: &'static str,

    // State <= Nothing
    // Input <= Nothing

    // Generate: client_nonce <- random
    //           gs2_header <- cb_flag ',' authzid

    // Output => ClientFirstMessage gs2_header ',' n=username ',' r=client_nonce

    // State => gs2_header, client_nonce, username
}

impl<const N: usize> StateClientFirst<N> {
    pub fn new() -> Self {
        Self { nonce: PhantomData }
    }

    pub fn send_client_first<D: Digest + BlockSizeUser + Clone + Sync>(
        self,
        rng: &mut impl Rng,
        cbflag: GS2CBindFlag<'_>,
        authzid: Option<String>,
        username: String,
        writer: impl Write,
        written: &mut usize,
    ) -> Result<WaitingServerFirst<D, N>, SessionError> {
        // The PRINTABLE slice is const not empty which is the only failure case we unwrap.
        let client_nonce: [u8; N] = generate_nonce(rng);

        let b =
            ClientFirstMessage::new(cbflag, authzid.as_ref(), &username, &client_nonce[..]).to_ioslices();

        let mut vecw = VectoredWriter::new(b);
        (*written) = vecw.write_all_vectored(writer)?;

        let gs2_header_len = b[0].len() + b[1].len() + b[2].len() + b[3].len();
        let mut gs2_header = Vec::with_capacity(gs2_header_len);

        // y | n | p=
        gs2_header.extend_from_slice(b[0]);
        // &[] | cbname
        gs2_header.extend_from_slice(b[1]);
        // b","
        gs2_header.extend_from_slice(b[2]);
        // authzid
        gs2_header.extend_from_slice(b[3]);
        // b","
        gs2_header.extend_from_slice(b",");

        Ok(WaitingServerFirst::new(gs2_header, client_nonce, username))
    }
}

// Waiting for first server msg
struct WaitingServerFirst<D: Digest + BlockSizeUser, const N: usize> {
    // Provided user password to be hashed with salt & iteration count from Server First Message
    //password: &'static str,
    //cbdata: Option<&[u8]>

    // State <= gs2_header, client_nonce, username
    gs2_header: Vec<u8>,
    // Need to compare combined_nonce to be valid
    client_nonce: [u8; N],

    username: String,
    // Input <= Server First Message { combined_nonce, salt, iteration_count }

    // Validate: len combined_nonce > len client_nonce
    //           combined_nonce `beginsWith` client_nonce

    // Generate: (proof, server_hmac) <- hash_with password salt iteration_count
    //           channel_binding <- base64_encode ( gs2_header ++ cb_data )

    // Output => ClientFinalMessage c=channel_binding,r=combined_nonce,p=proof
    // State => server_hmac
    digest: PhantomData<D>,
}

impl<D: Digest + BlockSizeUser + Clone + Sync, const N: usize> WaitingServerFirst<D, N> {
    pub fn new(gs2_header: Vec<u8>, client_nonce: [u8; N], username: String) -> Self {
        Self {
            gs2_header,
            client_nonce,
            username,
            digest: PhantomData,
        }
    }

    pub fn handle_server_first_salted(
        mut self,
        salted_password: &DOutput<D>,
        cbdata: Option<Box<[u8]>>,
        server_first: ServerFirst,
        writer: impl Write,
        written: &mut usize,
    ) -> Result<WaitingServerFinal<D>, SessionError> {
        self.gs2_header
            .extend_from_slice(cbdata.as_ref().map(|b| b.as_ref()).unwrap_or(&[]));
        let gs2headerb64 = base64::encode(self.gs2_header);

        let (client_proof, server_signature) =
            find_proofs::<D>(
                self.username.as_str(),
                &self.client_nonce[..],
                server_first,
                &gs2headerb64,
                salted_password,
            );

        let proof = base64::encode(client_proof.as_slice());

        let b = ClientFinal::new(gs2headerb64.as_bytes(), server_first.nonce, proof.as_bytes()).to_ioslices();

        let mut vecw = VectoredWriter::new(b);
        *written = vecw.write_all_vectored(writer)?;

        Ok(WaitingServerFinal::new(server_signature))
    }

    pub fn handle_server_first(
        self,
        password: &[u8],
        cbdata: Option<Box<[u8]>>,
        server_first: &[u8],
        writer: impl Write,
        written: &mut usize,
    ) -> Result<WaitingServerFinal<D>, SessionError> {
        let server_first @ ServerFirst {
            nonce,
            server_nonce: _,
            salt,
            iteration_count,
        } = ServerFirst::parse(server_first).map_err(SCRAMError::ParseError)?;

        if !(nonce.len() > self.client_nonce.len() && nonce.starts_with(&self.client_nonce[..])) {
            return Err(SCRAMError::Protocol(ProtocolError::InvalidNonce).into());
        }

        let iterations: u32 = std::str::from_utf8(iteration_count)
            .map_err(|_| SCRAMError::ParseError(super::parser::ParseError::BadUtf8))?
            .parse()
            .map_err(|_| SCRAMError::Protocol(ProtocolError::IterationCountFormat))?;

        if iterations == 0 {
            return Err(SCRAMError::Protocol(ProtocolError::IterationCountZero).into());
        }

        let salt = base64::decode(salt).unwrap();
        let mut salted_password = GenericArray::default();
        hash_password::<D>(password, iterations, &salt[..], &mut salted_password);

        self.handle_server_first_salted(&salted_password, cbdata, server_first, writer, written)
    }
}

// Waiting for final server msg
struct WaitingServerFinal<D: Digest + BlockSizeUser> {
    // State <= server_hmac
    server_sig: DOutput<D>,
    // Input <= Server Final Message ( verifier | error )

    // Validate: verifier == server_hmac
    //           no error

    // Output => Nothing
    // State => Nothing
}

impl<D: Digest + BlockSizeUser> WaitingServerFinal<D> {
    pub fn new(server_sig: DOutput<D>) -> Self {
        Self { server_sig }
    }

    pub fn handle_server_final(self, server_final: &[u8]) -> Result<StateServerFinal, SCRAMError> {
        match ServerFinal::parse(server_final)? {
            ServerFinal::Verifier(verifier) if verifier == self.server_sig.as_slice() => {
                Ok(StateServerFinal {})
            }
            ServerFinal::Verifier(_) => {
                Err(SCRAMError::Protocol(ProtocolError::ServerSignatureMismatch))
            }

            ServerFinal::Error(e) => Err(SCRAMError::ServerError(e)),
        }
    }
}

struct StateServerFinal {}

impl<D: Digest + BlockSizeUser + Clone + Sync, const N: usize> Authentication for ScramClient<D, N> {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> StepResult {
        use ScramClientState::*;
        match self.state.take() {
            Some(Initial(state)) => {
                /*
                let (_cbflag, _cbdata) = if self.plus {
                    let (name, value) = session
                        .get_cb_data()
                        // TODO: fix
                        .expect("CB data required");
                    (GS2CBindFlag::Used(name), Some(base64::encode(value)))
                } else {
                    (GS2CBindFlag::NotSupported, None)
                };
                 */

                let mut username = None;
                let mut outer_authzid = None;
                let mut outer_passwd = None;
                session.need_with::<'_, SimpleCredentials, _, _>(&(), &mut |Credentials { authid, authzid, password }| {
                    username = Some(SaslName::escape(authid).unwrap().into_owned());
                    outer_authzid = authzid.map(|s| s.to_string());
                    outer_passwd = Some(password.to_owned())
                })?;
                let username = username.unwrap();
                let authzid = outer_authzid;
                let password= outer_passwd.unwrap();


                let mut rng = rand::thread_rng();
                let mut written = 0;
                let new_state = state.step(
                    &mut rng,
                    authzid,
                    username,
                    writer,
                    &mut written,
                )?;
                self.state = Some(ClientFirst(new_state, password));

                Ok(NeedsMore(Some(written)))
            }
            Some(ClientFirst(state, password)) => {
                let server_first = input.ok_or(SessionError::InputDataRequired)?;

                let mut written = 0;
                let new_state = state.step(&password, server_first, writer, &mut written)?;
                self.state = Some(ServerFirst(new_state));

                Ok(NeedsMore(Some(written)))
            }
            Some(ServerFirst(state)) => {
                let server_final = input.ok_or(SessionError::InputDataRequired)?;
                state.step(server_final)?;
                Ok(Step::Done(None))
            }
            None => panic!("State machine in invalid state"),
        }
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub enum ProtocolError {
    InvalidNonce,
    IterationCountFormat,
    IterationCountZero,
    ServerSignatureMismatch,
}

impl Display for ProtocolError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::InvalidNonce => f.write_str("returned server nonce is invalid"),
            ProtocolError::IterationCountFormat => f.write_str("iteration count must be decimal"),
            ProtocolError::IterationCountZero => f.write_str("iteration count can't be zero"),
            ProtocolError::ServerSignatureMismatch => {
                f.write_str("Calculated server MAC and received server MAC do not match")
            }
        }
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub enum SCRAMError {
    Protocol(ProtocolError),
    ParseError(super::parser::ParseError),
    ServerError(ServerErrorValue),
}

impl From<super::parser::ParseError> for SCRAMError {
    fn from(e: super::parser::ParseError) -> Self {
        Self::ParseError(e)
    }
}

impl Display for SCRAMError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SCRAMError::Protocol(e) => write!(f, "SCRAM protocol error, {}", e),
            SCRAMError::ParseError(e) => write!(f, "SCRAM parse error, {}", e),
            SCRAMError::ServerError(e) => write!(f, "SCRAM outcome error, {}", e),
        }
    }
}

impl MechanismError for SCRAMError {
    fn kind(&self) -> MechanismErrorKind {
        match self {
            SCRAMError::Protocol(_) => MechanismErrorKind::Protocol,
            SCRAMError::ParseError(_) => MechanismErrorKind::Parse,
            SCRAMError::ServerError(_) => MechanismErrorKind::Outcome,
        }
    }
}

#[cfg(testn)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use crate::{Mechanism, Mechname, Side, SASL};

    use super::*;

    #[test]
    fn scram_test_1() {
        let mut sasl = SASL::new();
        const M: Mechanism = Mechanism {
            mechanism: Mechname::const_new_unvalidated(b"SCRAM"),
            priority: 0,
            client: Some(|_sasl| Ok(Box::new(ScramClient::<18>::new()))),
            server: None,
            first: Side::Client,
        };
        sasl.register(&M);
        let mut session = sasl.client_start(Mechname::new(b"SCRAM").unwrap()).unwrap();
        assert!(session.are_we_first());

        session.set_property::<AuthId>(Arc::new("testuser".to_string()));

        let mut out = Cursor::new(Vec::new());
        let data: Option<&[u8]> = None;

        let before = out.position() as usize;
        let stepout = session.step(data, &mut out).unwrap();
        let after = out.position() as usize;

        let sdata = &out.get_ref()[before..after];

        println!("({:?}): {}", stepout, std::str::from_utf8(sdata).unwrap());
        assert_eq!(stepout, Step::NeedsMore(Some(after - before)));
    }
}
