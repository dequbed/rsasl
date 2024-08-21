use crate::alloc::{string::String, vec::Vec};
use crate::callback::CallbackError;
use crate::context::{Demand, DemandReply, EmptyProvider, Provider};
use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::mechanism::Authentication;
use crate::mechanisms::scram::parser::{
    ClientFinal, SaslName, ServerErrorValue, ServerFinal, ServerFirst,
};
use crate::mechanisms::scram::properties::{Iterations, Salt, SaltedPassword, ScramCachedPassword};
use crate::mechanisms::scram::tools::{
    compute_signatures, derive_keys, generate_nonce, hash_password, DOutput,
};
use crate::property::{AuthId, AuthzId, OverrideCBType, Password};
use crate::session::{MechanismData, MessageSent, State};
use crate::vectored_io::VectoredWriter;
use base64::Engine;
use core::marker::PhantomData;
use core2::io::Write;
use digest::crypto_common::BlockSizeUser;
use digest::{Digest, FixedOutputReset};
use rand::Rng;
use thiserror::Error;

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
pub struct ScramClient<D: Digest + BlockSizeUser + FixedOutputReset, const N: usize> {
    state: Option<ScramClientState<D, N>>,
}

impl<D: Digest + BlockSizeUser + FixedOutputReset, const N: usize> ScramClient<D, N> {
    pub const fn new(set_cb_client_no_support: bool) -> Self {
        let plus = if set_cb_client_no_support {
            CbSupport::ClientNoSupport
        } else {
            CbSupport::ServerNoSupport
        };
        Self {
            state: Some(ScramClientState::Initial(ScramState::new(plus))),
        }
    }

    pub const fn new_plus() -> Self {
        Self {
            state: Some(ScramClientState::Initial(ScramState::new(
                CbSupport::Supported,
            ))),
        }
    }
}

enum ScramClientState<D: Digest + BlockSizeUser + FixedOutputReset, const N: usize> {
    Initial(ScramState<StateClientFirst<N>>),
    ClientFirst(ScramState<WaitingServerFirst<D, N>>),
    ServerFirst(ScramState<WaitingServerFinal<D>>),
}

struct ScramState<S> {
    state: S,
}

impl<const N: usize> ScramState<StateClientFirst<N>> {
    pub const fn new(plus: CbSupport) -> Self {
        Self {
            state: StateClientFirst::new(plus),
        }
    }

    pub fn step<D>(
        self,
        rng: &mut impl Rng,
        session_data: &mut MechanismData,
        writer: impl Write,
        written: &mut usize,
    ) -> Result<ScramState<WaitingServerFirst<D, N>>, SessionError>
    where
        D: Digest + BlockSizeUser + FixedOutputReset + Clone + Sync,
    {
        let state = self
            .state
            .send_client_first(rng, session_data, writer, written)?;
        Ok(ScramState { state })
    }
}

impl<D, const N: usize> ScramState<WaitingServerFirst<D, N>>
where
    D: Digest + BlockSizeUser + FixedOutputReset + Clone + Sync,
{
    pub fn step(
        self,
        session_data: &mut MechanismData,
        server_first: &[u8],
        writer: impl Write,
        written: &mut usize,
    ) -> Result<ScramState<WaitingServerFinal<D>>, SessionError> {
        let state = self
            .state
            .handle_server_first(session_data, server_first, writer, written)?;
        Ok(ScramState { state })
    }
}

impl<D: Digest + BlockSizeUser> ScramState<WaitingServerFinal<D>> {
    pub fn step(
        self,
        session: &mut MechanismData,
        server_final: &[u8],
    ) -> Result<(), SessionError> {
        match self.state.handle_server_final(session, server_final) {
            Ok(StateServerFinal { .. }) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

struct StateClientFirst<const N: usize> {
    plus: CbSupport,
    nonce: PhantomData<&'static [u8; N]>,
    // Parameters Data required to send Client First Message
    //cb_flag: Option<&'static str>,
    //authzid: Option<&'static str>,
    //username: &'static str,

    // State <= Nothing
    // Input <= Nothing

    // Generate: client_nonce <- random
    //           gs2_header <- cb_flag ',' authzid ','

    // Output => ClientFirstMessage gs2_header n=username ',' r=client_nonce

    // State => gs2_header, client_nonce, username
}

impl<const N: usize> StateClientFirst<N> {
    pub const fn new(plus: CbSupport) -> Self {
        Self {
            plus,
            nonce: PhantomData,
        }
    }

    pub fn send_client_first<D>(
        self,
        rng: &mut impl Rng,
        session: &mut MechanismData,
        writer: impl Write,
        written: &mut usize,
    ) -> Result<WaitingServerFirst<D, N>, SessionError>
    where
        D: Digest + BlockSizeUser + FixedOutputReset + Clone + Sync,
    {
        let mut gs2_header = Vec::new();
        let mut cbdata: Option<Vec<u8>> = None;

        match self.plus {
            CbSupport::Supported => {
                gs2_header.extend_from_slice(b"p=");
                let cbtype =
                    session.maybe_need_with::<OverrideCBType, _, _>(&EmptyProvider, |cbname| {
                        gs2_header.extend_from_slice(cbname.as_bytes());
                        Ok(cbname.to_string())
                    })?;

                if let Some(cbname) = cbtype.as_deref() {
                    session.need_cb_data(cbname, EmptyProvider, |i_cbdata| {
                        cbdata = Some(i_cbdata.into());
                        Ok(())
                    })?;
                } else {
                    let exporter =
                        session.maybe_need_cb_data("tls-exporter", EmptyProvider, |i_cbdata| {
                            gs2_header.extend_from_slice(b"tls-exporter");
                            cbdata = Some(i_cbdata.into());
                            Ok(())
                        })?;
                    if exporter.is_none() {
                        session.need_cb_data("tls-unique", EmptyProvider, |i_cbdata| {
                            gs2_header.extend_from_slice(b"tls-unique");
                            cbdata = Some(i_cbdata.into());
                            Ok(())
                        })?;
                    }
                }
            }
            CbSupport::ServerNoSupport => gs2_header.push(b'y'),
            CbSupport::ClientNoSupport => gs2_header.push(b'n'),
        };
        gs2_header.push(b',');

        session.maybe_need_with::<AuthzId, _, _>(&EmptyProvider, |authzid| {
            gs2_header.extend_from_slice(b"a=");
            let escaped = SaslName::escape(authzid)?;
            gs2_header.extend_from_slice(escaped.as_bytes());
            Ok(())
        })?;
        gs2_header.push(b',');

        let username = session.need_with::<AuthId, _, _>(&EmptyProvider, |authid| {
            Ok(SaslName::escape(authid)?.to_string())
        })?;

        let client_nonce: [u8; N] = generate_nonce(rng);

        let iovecs = [
            &gs2_header[..],
            b"n=",
            username.as_bytes(),
            b",r=",
            &client_nonce,
        ];
        let mut vecw = VectoredWriter::new(iovecs);
        (*written) = vecw.write_all_vectored(writer)?;

        if let Some(cbdata) = cbdata {
            gs2_header.extend_from_slice(&cbdata[..]);
        }
        let channel_bindings = base64::engine::general_purpose::STANDARD.encode(&gs2_header[..]);

        Ok(WaitingServerFirst::new(
            channel_bindings,
            client_nonce,
            username,
        ))
    }
}

// Waiting for first server msg
struct WaitingServerFirst<D, const N: usize> {
    // base64-encoded channel bindings, i.e. the attribute to send with 'c=' in client final.
    channel_bindings: String,
    // The generated client nonce
    client_nonce: [u8; N],
    // Authid
    username: String,

    // Marker for the digest in use
    digest: PhantomData<D>,
}

impl<D, const N: usize> WaitingServerFirst<D, N>
where
    D: Digest + BlockSizeUser + FixedOutputReset + Clone + Sync,
{
    pub const fn new(channel_bindings: String, client_nonce: [u8; N], username: String) -> Self {
        Self {
            channel_bindings,
            client_nonce,
            username,
            digest: PhantomData,
        }
    }

    pub fn handle_server_first(
        self,
        session_data: &mut MechanismData,
        input: &[u8],
        writer: impl Write,
        written: &mut usize,
    ) -> Result<WaitingServerFinal<D>, SessionError> {
        let _server_first @ ServerFirst {
            nonce,
            server_nonce: _,
            salt: salt64,
            iteration_count,
        } = ServerFirst::parse(input).map_err(SCRAMError::ParseError)?;

        let server_nonce = nonce
            .strip_prefix(&self.client_nonce)
            .ok_or(SCRAMError::Protocol(ProtocolError::InvalidNonce))?;
        if server_nonce.is_empty() {
            return Err(SCRAMError::Protocol(ProtocolError::InvalidNonce).into());
        }

        let iterations: u32 = core::str::from_utf8(iteration_count)
            .map_err(|e| SCRAMError::ParseError(super::parser::ParseError::BadUtf8(e)))?
            .parse()
            .map_err(|_| SCRAMError::Protocol(ProtocolError::IterationCountFormat))?;

        if iterations == 0 {
            return Err(SCRAMError::Protocol(ProtocolError::IterationCountZero).into());
        }

        let salt = base64::engine::general_purpose::STANDARD
            .decode(salt64)
            .map_err(|_| SCRAMError::Protocol(ProtocolError::Base64Decode))?;

        let prov = ScramClientProvider {
            iterations: &iterations,
            salt: &salt[..],
        };

        // first, see if the user has cached the keys directly. This is the best case with the
        // least work to be done.
        let mut keys: Option<(DOutput<D>, DOutput<D>)>;
        keys = session_data.maybe_need_with::<ScramCachedPassword, _, _>(
            &prov,
            |ScramCachedPassword {
                 client_key,
                 server_key,
             }| {
                Ok((
                    DOutput::<D>::clone_from_slice(client_key),
                    DOutput::<D>::clone_from_slice(server_key),
                ))
            },
        )?;

        // If the user has not cached the keys directly, maybe they have cached the salted
        // password. This still skips the biggest amount of work, namely running PBKDF2
        // TODO: This is probably really unlikely over having the actual keys cached. Remove?
        if keys.is_none() {
            keys = session_data.maybe_need_with::<SaltedPassword, _, _>(&prov, |password| {
                if password.is_empty() {
                    return Err(SessionError::CallbackError(CallbackError::NoValue));
                }

                Ok(derive_keys::<D>(password))
            })?;
        }

        // If none of the above succeeded, we generate the keys from the plain text password. If
        // this *also* doesn't work, we error out of the authentication.
        if keys.is_none() {
            keys = Some(
                session_data.need_with::<Password, _, _>(&prov, |plain_password| {
                    let mut salted_password = DOutput::<D>::default();

                    // Derive the PBKDF2 key from the password and salt. This is the expensive part
                    hash_password::<D>(plain_password, iterations, &salt[..], &mut salted_password);

                    Ok(derive_keys::<D>(salted_password.as_slice()))
                })?,
            );
        }

        // We now have gotten ourself the keys as efficiently as we could.
        let (client_key, server_key) = keys.unwrap();
        let stored_key = D::digest(&client_key);

        let mut client_signature = DOutput::<D>::default();
        let mut server_signature = DOutput::<D>::default();

        compute_signatures::<D>(
            &stored_key,
            &server_key,
            &self.username,
            &self.client_nonce,
            server_nonce,
            salt64,
            iteration_count,
            self.channel_bindings.as_bytes(),
            &mut client_signature,
            &mut server_signature,
        );

        let proof = DOutput::<D>::from_exact_iter(
            client_key.iter().zip(client_signature).map(|(x, y)| x ^ y),
        )
        .expect("XOR of two same-sized arrays was not of that size?");
        let proof64 = base64::engine::general_purpose::STANDARD.encode(&proof);

        let client_final =
            ClientFinal::new(self.channel_bindings.as_bytes(), nonce, proof64.as_bytes())
                .to_ioslices();

        let mut vecw = VectoredWriter::new(client_final);
        *written = vecw.write_all_vectored(writer)?;

        Ok(WaitingServerFinal::new(
            server_signature,
            client_key,
            server_key,
            salt,
            iterations,
        ))
    }
}

// Waiting for final server msg
struct WaitingServerFinal<D: Digest + BlockSizeUser> {
    verifier: DOutput<D>,
    client_key: DOutput<D>,
    server_key: DOutput<D>,
    salt: Vec<u8>,
    iterations: u32,
}

impl<D: Digest + BlockSizeUser> WaitingServerFinal<D> {
    pub fn new(
        verifier: DOutput<D>,
        client_key: DOutput<D>,
        server_key: DOutput<D>,
        salt: Vec<u8>,
        iterations: u32,
    ) -> Self {
        Self {
            verifier,
            client_key,
            server_key,
            salt,
            iterations,
        }
    }

    pub fn handle_server_final(
        self,
        session: &mut MechanismData,
        server_final: &[u8],
    ) -> Result<StateServerFinal, SessionError> {
        match ServerFinal::parse(server_final).map_err(SCRAMError::ParseError)? {
            ServerFinal::Verifier(verifier) => {
                let v = base64::engine::general_purpose::STANDARD
                    .decode(verifier)
                    .map_err(|_| SCRAMError::Protocol(ProtocolError::Base64Decode))?;

                if self.verifier.as_slice() == &v[..] {
                    let prov = ScramClientProvider {
                        salt: &self.salt[..],
                        iterations: &self.iterations,
                    };

                    // `let _` because the client doesn't have to save the generated keys
                    let _unused = session.action::<ScramCachedPassword>(
                        &prov,
                        &ScramCachedPassword {
                            client_key: self.client_key.as_slice(),
                            server_key: self.server_key.as_slice(),
                        },
                    );
                    Ok(StateServerFinal {})
                } else {
                    Err(SessionError::MutualAuthenticationFailed)
                }
            }
            ServerFinal::Error(e) => Err(SCRAMError::ServerError(e).into()),
        }
    }
}

struct StateServerFinal {}

impl<D, const N: usize> Authentication for ScramClient<D, N>
where
    D: Digest + BlockSizeUser + FixedOutputReset + Clone + Send + Sync,
{
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<State, SessionError> {
        use ScramClientState::{ClientFirst, Initial, ServerFirst};
        match self.state.take() {
            Some(Initial(state)) => {
                let mut rng = rand::thread_rng();
                let mut written = 0;
                let new_state = state.step(&mut rng, session, writer, &mut written)?;
                self.state = Some(ClientFirst(new_state));

                Ok(State::Running)
            }
            Some(ClientFirst(state)) => {
                let server_first = input.ok_or(SessionError::InputDataRequired)?;

                let mut written = 0;
                let new_state = state.step(session, server_first, writer, &mut written)?;
                self.state = Some(ServerFirst(new_state));

                Ok(State::Running)
            }
            Some(ServerFirst(state)) => {
                let server_final = input.ok_or(SessionError::InputDataRequired)?;
                state.step(session, server_final)?;
                Ok(State::Finished(MessageSent::No))
            }
            None => panic!("State machine in invalid state"),
        }
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Error)]
pub enum ProtocolError {
    #[error("returned server nonce is invalid")]
    InvalidNonce,
    #[error("iteration count must be decimal")]
    IterationCountFormat,
    #[error("iteration count can't be zero")]
    IterationCountZero,
    #[error("base64 decoding of data failed")]
    Base64Decode,
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
            Self::Protocol(_) => MechanismErrorKind::Protocol,
            Self::ParseError(_) => MechanismErrorKind::Parse,
            Self::ServerError(_) => MechanismErrorKind::Outcome,
        }
    }
}

struct ScramClientProvider<'a> {
    iterations: &'a u32,
    salt: &'a [u8],
}
impl<'a> Provider<'a> for ScramClientProvider<'a> {
    fn provide(&self, req: &mut Demand<'a>) -> DemandReply<()> {
        req.provide_ref::<Salt>(self.salt)?
            .provide_ref::<Iterations>(self.iterations)?
            .done()
    }
}

#[cfg(test)]
mod tests {
    use digest::Update;
    use hmac::{Mac, SimpleHmac};
    use rand::random;

    #[test]
    // Test an assertion about how resetting hmac behaves
    fn test_hmac_reset_assumption() {
        let key: [u8; 32] = random();

        let mut hmac = <SimpleHmac<sha2::Sha256>>::new_from_slice(&key)
            .expect("HMAC should work with every key length");

        Mac::update(&mut hmac, b"Client Key");
        let client_key = hmac.finalize_reset().into_bytes();

        Mac::update(&mut hmac, b"Server Key");
        let server_key = hmac.finalize().into_bytes();

        let hmac2 = <SimpleHmac<sha2::Sha256>>::new_from_slice(&key)
            .expect("HMAC should work with every key length");
        let client_key2 = hmac2.chain(b"Client Key").finalize().into_bytes();

        let hmac3 = <SimpleHmac<sha2::Sha256>>::new_from_slice(&key)
            .expect("HMAC should work with every key length");
        let server_key2 = hmac3.chain(b"Server Key").finalize().into_bytes();

        assert_eq!(client_key, client_key2);
        assert_eq!(server_key, server_key2);
    }
}
