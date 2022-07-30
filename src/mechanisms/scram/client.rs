use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use std::io::Write;
use std::marker::PhantomData;

use thiserror::Error;

use digest::crypto_common::BlockSizeUser;
use digest::generic_array::GenericArray;
use digest::Digest;

use rand::Rng;

use crate::context::EmptyProvider;
use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::mechanism::Authentication;

use crate::mechanisms::scram::parser::{
    ClientFinal, ClientFirstMessage, GS2CBindFlag, SaslName, ServerErrorValue, ServerFinal,
    ServerFirst,
};
use crate::mechanisms::scram::tools::{find_proofs, generate_nonce, hash_password, DOutput};
use crate::property::{AuthId, AuthzId, OverrideCBType, Password};
use crate::session::{MechanismData, State};
use crate::vectored_io::VectoredWriter;

#[cfg(feature = "scram-sha-2")]
pub type ScramSha256Client<const N: usize> = ScramClient<sha2::Sha256, N>;
#[cfg(feature = "scram-sha-2")]
pub type ScramSha512Client<const N: usize> = ScramClient<sha2::Sha512, N>;

#[cfg(feature = "scram-sha-1")]
pub type ScramSha1Client<const N: usize> = ScramClient<sha1::Sha1, N>;

enum CbSupport {
    ClientNoSupport,
    ServerNoSupport,
    Supported,
}
pub struct ScramClient<D: Digest + BlockSizeUser + Clone + Sync, const N: usize> {
    plus: CbSupport,
    state: Option<ScramClientState<D, N>>,
}

impl<D: Digest + BlockSizeUser + Clone + Sync, const N: usize> ScramClient<D, N> {
    pub fn new(set_cb_client_no_support: bool) -> Self {
        let plus = if set_cb_client_no_support {
            CbSupport::ClientNoSupport
        } else {
            CbSupport::ServerNoSupport
        };
        Self {
            // TODO: Actually, how *do* we figure this out?
            plus,
            state: Some(ScramClientState::Initial(ScramState::new())),
        }
    }

    pub fn new_plus() -> Self {
        Self {
            plus: CbSupport::Supported,
            state: Some(ScramClientState::Initial(ScramState::new())),
        }
    }
}

enum ScramClientState<D: Digest + BlockSizeUser, const N: usize> {
    Initial(ScramState<StateClientFirst<N>>),
    ClientFirst(ScramState<WaitingServerFirst<D, N>>, Vec<u8>),
    ServerFirst(ScramState<WaitingServerFinal<D>>),
}

struct ScramState<S> {
    state: S,
}

impl<const N: usize> ScramState<StateClientFirst<N>> {
    pub fn new() -> Self {
        Self {
            state: StateClientFirst::new(),
        }
    }

    pub fn step<D: Digest + BlockSizeUser + Clone + Sync>(
        self,
        rng: &mut impl Rng,
        cbflag: GS2CBindFlag<'_>,
        cbdata: Option<String>,
        authzid: Option<String>,
        username: String,
        writer: impl Write,
        written: &mut usize,
    ) -> Result<ScramState<WaitingServerFirst<D, N>>, SessionError> {
        let state = self
            .state
            .send_client_first(rng, cbflag, cbdata, authzid, username, writer, written)?;
        Ok(ScramState { state })
    }
}

impl<D: Digest + BlockSizeUser + Clone + Sync, const N: usize>
    ScramState<WaitingServerFirst<D, N>>
{
    pub fn step(
        self,
        password: &[u8],
        server_first: &[u8],
        writer: impl Write,
        written: &mut usize,
    ) -> Result<ScramState<WaitingServerFinal<D>>, SessionError> {
        let state = self
            .state
            .handle_server_first(password, server_first, writer, written)?;
        Ok(ScramState { state })
    }
}

impl<D: Digest + BlockSizeUser> ScramState<WaitingServerFinal<D>> {
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
        cbdata: Option<String>,
        authzid: Option<String>,
        username: String,
        writer: impl Write,
        written: &mut usize,
    ) -> Result<WaitingServerFirst<D, N>, SessionError> {
        // The PRINTABLE slice is const not empty which is the only failure case we unwrap.
        let client_nonce: [u8; N] = generate_nonce(rng);

        let b = ClientFirstMessage::new(cbflag, authzid.as_ref(), &username, &client_nonce[..])
            .to_ioslices();

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

        Ok(WaitingServerFirst::new(
            cbdata,
            gs2_header,
            client_nonce,
            username,
        ))
    }
}

// Waiting for first server msg
struct WaitingServerFirst<D: Digest + BlockSizeUser, const N: usize> {
    // Provided user password to be hashed with salt & iteration count from Server First Message
    //password: &'static str,
    cbdata: Option<String>,

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
    pub fn new(
        cbdata: Option<String>,
        gs2_header: Vec<u8>,
        client_nonce: [u8; N],
        username: String,
    ) -> Self {
        Self {
            cbdata,
            gs2_header,
            client_nonce,
            username,
            digest: PhantomData,
        }
    }

    pub fn handle_server_first_salted(
        mut self,
        salted_password: &DOutput<D>,
        server_first: ServerFirst,
        writer: impl Write,
        written: &mut usize,
    ) -> Result<WaitingServerFinal<D>, SessionError> {
        self.cbdata
            .take()
            .map(|cbdata| self.gs2_header.extend_from_slice(cbdata.as_bytes()));
        let gs2headerb64 = base64::encode(self.gs2_header);

        let (client_proof, server_signature) = find_proofs::<D>(
            self.username.as_str(),
            &self.client_nonce[..],
            server_first,
            &gs2headerb64,
            salted_password,
        );

        let proof = base64::encode(client_proof.as_slice());

        let b = ClientFinal::new(
            gs2headerb64.as_bytes(),
            server_first.nonce,
            proof.as_bytes(),
        )
        .to_ioslices();

        let mut vecw = VectoredWriter::new(b);
        *written = vecw.write_all_vectored(writer)?;

        Ok(WaitingServerFinal::new(server_signature))
    }

    pub fn handle_server_first(
        self,
        password: &[u8],
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
            .map_err(|e| SCRAMError::ParseError(super::parser::ParseError::BadUtf8(e)))?
            .parse()
            .map_err(|_| SCRAMError::Protocol(ProtocolError::IterationCountFormat))?;

        if iterations == 0 {
            return Err(SCRAMError::Protocol(ProtocolError::IterationCountZero).into());
        }

        let salt = base64::decode(salt).unwrap();
        let mut salted_password = GenericArray::default();
        hash_password::<D>(password, iterations, &salt[..], &mut salted_password);

        self.handle_server_first_salted(&salted_password, server_first, writer, written)
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

impl<D: Digest + BlockSizeUser + Clone + Sync, const N: usize> Authentication
    for ScramClient<D, N>
{
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<(State, Option<usize>), SessionError> {
        use ScramClientState::*;
        match self.state.take() {
            Some(Initial(state)) => {
                let mut cbname = Cow::Borrowed("tls-unique");
                let mut cbdata = None;
                let cbflag = match self.plus {
                    CbSupport::Supported => {
                        let res = session.need_with::<OverrideCBType, _, _>(
                            &EmptyProvider,
                            &mut |i_cbname| {
                                session.need_cb_data(i_cbname, EmptyProvider, &mut |i_cbdata| {
                                    cbdata = Some(base64::encode(i_cbdata));
                                    Ok(())
                                })?;
                                cbname = Cow::Owned(i_cbname.into());
                                Ok(())
                            },
                        );
                        match res {
                            Ok(()) => {}
                            Err(e) if e.is_missing_prop() => {
                                session.need_cb_data(
                                    "tls-unique",
                                    EmptyProvider,
                                    &mut |i_cbdata| {
                                        cbdata = Some(base64::encode(i_cbdata));
                                        Ok(())
                                    },
                                )?;
                            }
                            Err(other) => return Err(other.into()),
                        }

                        GS2CBindFlag::Used(&cbname)
                    }
                    CbSupport::ServerNoSupport => GS2CBindFlag::SupportedNotUsed,
                    CbSupport::ClientNoSupport => GS2CBindFlag::NotSupported,
                };

                let provider = EmptyProvider;
                let username = session.need_with::<AuthId, _, _>(&provider, &mut |authid| {
                    Ok(SaslName::escape(authid)?.into_owned())
                })?;
                let authzid = session
                    .maybe_need_with::<AuthzId, _, _>(&provider, &mut |authzid| {
                        Ok(SaslName::escape(authzid)?.into_owned())
                    })?;
                let password = session.need_with::<Password, _, _>(&provider, &mut |password| {
                    Ok(password.to_vec())
                })?;

                let mut rng = rand::thread_rng();
                let mut written = 0;
                let new_state = state.step(
                    &mut rng,
                    cbflag,
                    cbdata,
                    authzid,
                    username,
                    writer,
                    &mut written,
                )?;
                self.state = Some(ClientFirst(new_state, password));

                Ok((State::Running, Some(written)))
            }
            Some(ClientFirst(state, password)) => {
                let server_first = input.ok_or(SessionError::InputDataRequired)?;

                let mut written = 0;
                let new_state = state.step(&password, server_first, writer, &mut written)?;
                self.state = Some(ServerFirst(new_state));

                Ok((State::Running, Some(written)))
            }
            Some(ServerFirst(state)) => {
                let server_final = input.ok_or(SessionError::InputDataRequired)?;
                state.step(server_final)?;
                Ok((State::Finished, None))
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

#[derive(Debug, Eq, PartialEq, Copy, Clone, Error)]
pub enum SCRAMError {
    #[error("SCRAM protocol error: {0}")]
    Protocol(ProtocolError),
    #[error("failed to parse received message: {0}")]
    ParseError(
        #[from]
        #[source]
        super::parser::ParseError,
    ),
    #[error("SCRAM outcome error: {0}")]
    ServerError(ServerErrorValue),
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