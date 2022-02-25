use std::fmt::{Display, Formatter};
use std::io::Write;
use std::marker::PhantomData;
use std::ptr::NonNull;

use ::libc;
use hmac::Hmac;
use libc::{calloc, malloc, memcmp, memcpy, size_t, strchr, strcmp, strdup, strlen};
use rand::distributions::{Distribution, Slice};
use rand::Rng;

use crate::error::{MechanismError, MechanismErrorKind, SessionError};
use crate::gsasl::base64::{gsasl_base64_from, gsasl_base64_to};
use crate::gsasl::consts::{
    GSASL_AUTHENTICATION_ERROR, GSASL_AUTHID, GSASL_AUTHZID, GSASL_CB_TLS_UNIQUE,
    GSASL_MALLOC_ERROR, GSASL_MECHANISM_CALLED_TOO_MANY_TIMES, GSASL_MECHANISM_PARSE_ERROR,
    GSASL_NEEDS_MORE, GSASL_NO_AUTHID, GSASL_NO_CB_TLS_UNIQUE, GSASL_NO_PASSWORD, GSASL_OK,
    GSASL_PASSWORD, GSASL_SCRAM_ITER, GSASL_SCRAM_SALT, GSASL_SCRAM_SALTED_PASSWORD,
};
use crate::gsasl::crypto::{
    gsasl_hash_length, gsasl_nonce, gsasl_scram_secrets_from_password,
    gsasl_scram_secrets_from_salted_password,
};
use crate::gsasl::free::gsasl_free;
use crate::gsasl::gl::free::rpl_free;
use crate::gsasl::gl::memxor::memxor;
use crate::gsasl::mechtools::{
    Gsasl_hash, _gsasl_hex_decode, _gsasl_hex_p, _gsasl_hmac, GSASL_HASH_SHA1, GSASL_HASH_SHA256,
};
use crate::gsasl::property::{gsasl_property_get, gsasl_property_set};
use crate::gsasl::saslprep::{gsasl_saslprep, GSASL_ALLOW_UNASSIGNED};
use crate::mechanisms::scram::parser::{
    scram_parse_server_final, scram_parse_server_first, ClientFinal, ClientFirstMessage,
    GS2CBindFlag, SaslName, ServerErrorValue, ServerFinal, ServerFirst,
};
use crate::mechanisms::scram::printer::{scram_print_client_final, scram_print_client_first};
use crate::mechanisms::scram::server::{scram_server_final, scram_server_first};
use crate::mechanisms::scram::tokens::{
    scram_free_client_final, scram_free_client_first, scram_free_server_final,
    scram_free_server_first,
};
use crate::mechanisms::scram::tools::{find_proofs, hash_password, set_saltedpassword};
use crate::property::{AuthId, AuthzId, Password};
use crate::session::Step::NeedsMore;
use crate::session::{SessionData, Step, StepResult};
use crate::vectored_io::VectoredWriter;
use crate::{Authentication, Shared};

/// All the characters that are valid chars for a nonce
const PRINTABLE: &'static [u8] =
    b"!\"#$%&'()*+-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy";

pub struct ScramClient<const N: usize> {
    plus: bool,
    state: Option<ScramClientState<N>>,
}

impl<const N: usize> ScramClient<N> {
    pub fn new() -> Self {
        Self {
            plus: false,
            state: Some(ScramClientState::Initial(State::new(None))),
        }
    }
}

enum ScramClientState<const N: usize> {
    Initial(State<StateClientFirst<N>>),
    ClientFirst(State<WaitingServerFirst<N>>),
    ServerFirst(State<WaitingServerFinal<32>>),
    Done(State<StateServerFinal>),
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

    pub fn step(
        self,
        rng: &mut impl Rng,
        authzid: Option<&str>,
        username: Box<SaslName>,
        writer: impl Write,
        written: &mut usize,
    ) -> Result<State<WaitingServerFirst<N>>, SessionError> {
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

impl<const N: usize> State<WaitingServerFirst<N>> {
    pub fn step(
        self,
        password: &str,
        server_first: &[u8],
        writer: impl Write,
        written: &mut usize,
    ) -> Result<State<WaitingServerFinal<32>>, SessionError> {
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

impl<const N: usize> State<WaitingServerFinal<N>> {
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

    pub fn send_client_first(
        self,
        rng: &mut impl Rng,
        cbflag: GS2CBindFlag<'_>,
        authzid: Option<&str>,
        username: Box<SaslName>,
        writer: impl Write,
        written: &mut usize,
    ) -> Result<WaitingServerFirst<N>, SessionError> {
        // The PRINTABLE slice is const not empty which is the only failure case we unwrap.
        let distribution = Slice::new(PRINTABLE).unwrap();
        let client_nonce: [u8; N] = [0u8; N].map(|_| *distribution.sample(rng));

        let b =
            ClientFirstMessage::new(cbflag, authzid, &username, &client_nonce[..]).to_ioslices();

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
struct WaitingServerFirst<const N: usize> {
    // Provided user password to be hashed with salt & iteration count from Server First Message
    //password: &'static str,
    //cbdata: Option<&[u8]>

    // State <= gs2_header, client_nonce, username
    gs2_header: Vec<u8>,
    // Need to compare combined_nonce to be valid
    client_nonce: [u8; N],

    username: Box<SaslName>,
    // Input <= Server First Message { combined_nonce, salt, iteration_count }

    // Validate: len combined_nonce > len client_nonce
    //           combined_nonce `beginsWith` client_nonce

    // Generate: (proof, server_hmac) <- hash_with password salt iteration_count
    //           channel_binding <- base64_encode ( gs2_header ++ cb_data )

    // Output => ClientFinalMessage c=channel_binding,r=combined_nonce,p=proof
    // State => server_hmac
}

impl<const N: usize> WaitingServerFirst<N> {
    pub fn new(gs2_header: Vec<u8>, client_nonce: [u8; N], username: Box<SaslName>) -> Self {
        Self {
            gs2_header,
            client_nonce,
            username,
        }
    }

    pub fn handle_server_first(
        mut self,
        password: &str,
        cbdata: Option<Box<[u8]>>,
        server_first: &[u8],
        writer: impl Write,
        written: &mut usize,
    ) -> Result<WaitingServerFinal<32>, SessionError> {
        let ServerFirst {
            nonce,
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
        let mut salted_password = [0u8; 32];
        hash_password::<Hmac<sha2::Sha256>>(password, iterations, &salt[..], &mut salted_password);

        self.gs2_header
            .extend_from_slice(cbdata.as_ref().map(|b| b.as_ref()).unwrap_or(&[]));
        let gs2headerb64 = base64::encode(self.gs2_header);

        let (client_proof, server_signature) =
            find_proofs::<sha2::Sha256, Hmac<sha2::Sha256>, digest::consts::U32>(
                self.username.as_str(),
                &self.client_nonce[..],
                server_first,
                &gs2headerb64,
                nonce,
                &salted_password[..],
            );

        let proof = base64::encode(client_proof.as_slice());

        let b = ClientFinal::new(gs2headerb64.as_bytes(), nonce, proof.as_bytes()).to_ioslices();

        let mut vecw = VectoredWriter::new(b);
        *written = vecw.write_all_vectored(writer)?;

        let mut server_sig = [0u8; 32];
        server_sig.copy_from_slice(server_signature.as_ref());

        Ok(WaitingServerFinal::new(server_sig))
    }
}

// Waiting for final server msg
struct WaitingServerFinal<const H: usize> {
    // State <= server_hmac
    server_sig: [u8; H],
    // Input <= Server Final Message ( verifier | error )

    // Validate: verifier == server_hmac
    //           no error

    // Output => Nothing
    // State => Nothing
}

impl<const H: usize> WaitingServerFinal<H> {
    pub fn new(server_sig: [u8; H]) -> Self {
        Self { server_sig }
    }

    pub fn handle_server_final(self, server_final: &[u8]) -> Result<StateServerFinal, SCRAMError> {
        match ServerFinal::parse(server_final)? {
            ServerFinal::Verifier(verifier) if verifier == self.server_sig => {
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

impl<const N: usize> Authentication for ScramClient<N> {
    fn step(
        &mut self,
        session: &mut SessionData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> StepResult {
        use ScramClientState::*;
        match self.state.take() {
            Some(Initial(state)) => {
                let (_cbflag, _cbdata) = if self.plus {
                    let (name, value) = session
                        .get_cb_data()
                        // TODO: fix
                        .expect("CB data required");
                    (GS2CBindFlag::Used(name), Some(base64::encode(value)))
                } else {
                    (GS2CBindFlag::NotSupported, None)
                };

                let authzid = session.get_property_or_callback::<AuthzId>()?;
                let authid = session
                    .get_property_or_callback::<AuthId>()?
                    .ok_or(SessionError::no_property::<AuthId>())?;
                let username_escaped = SaslName::escape(&authid).unwrap();
                let username =
                    SaslName::from_boxed_str(username_escaped.into_owned().into_boxed_str())
                        .expect("escaped SaslName contained invalid chars");

                let mut rng = rand::thread_rng();
                let mut written = 0;
                let new_state = state.step(
                    &mut rng,
                    authzid.as_ref().map(|arc| arc.as_str()),
                    username,
                    writer,
                    &mut written,
                )?;
                self.state = Some(ClientFirst(new_state));

                Ok(NeedsMore(Some(written)))
            }
            Some(ClientFirst(state)) => {
                let server_first = input.ok_or(SessionError::InputDataRequired)?;

                let password = session
                    .get_property_or_callback::<Password>()?
                    .ok_or(SessionError::no_property::<Password>())?;

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
            Some(Done(_)) => panic!("State machine polled after completion"),
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use crate::{Mechanism, Mechname, Side, SASL};

    use super::*;

    #[test]
    fn scram_test_1() {
        let mut sasl = SASL::new();
        const M: Mechanism = Mechanism {
            mechanism: Mechname::const_new_unchecked(b"SCRAM"),
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

extern "C" {
    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char, _: ...) -> libc::c_int;
}

/* Crypto functions: crypto.c */
/* *
 * Gsasl_hash:
 * @GSASL_HASH_SHA1: Hash function SHA-1.
 * @GSASL_HASH_SHA256: Hash function SHA-256.
 *
 * Hash functions.  You may use gsasl_hash_length() to get the
 * output size of a hash function.
 *
 * Currently only used as parameter to
 * gsasl_scram_secrets_from_salted_password() and
 * gsasl_scram_secrets_from_password() to specify for which SCRAM
 * mechanism to prepare secrets for.
 *
 * Since: 1.10
 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_client_state {
    pub plus: bool,
    pub hash: Gsasl_hash,
    pub step: libc::c_int,
    pub cfmb: *mut libc::c_char,
    pub serversignature: *mut libc::c_char,
    pub authmessage: *mut libc::c_char,
    pub cbtlsunique: *mut libc::c_char,
    pub cbtlsuniquelen: size_t,
    pub cf: scram_client_first,
    pub sf: scram_server_first,
    pub cl: scram_client_final,
    pub sl: scram_server_final,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_client_final {
    pub cbind: *mut libc::c_char,
    pub nonce: *mut libc::c_char,
    pub proof: *mut libc::c_char,
}

/* tokens.h --- Types for SCRAM tokens.
 * Copyright (C) 2009-2021 Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */
/* Get size_t. */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_client_first {
    pub cbflag: libc::c_char,
    pub cbname: *mut libc::c_char,
    pub authzid: *mut libc::c_char,
    pub username: *mut libc::c_char,
    pub client_nonce: *mut libc::c_char,
}

unsafe fn scram_start(
    mut _sctx: &Shared,
    mech_data: *mut *mut libc::c_void,
    plus: bool,
    hash: Gsasl_hash,
) -> libc::c_int {
    let mut state: *mut scram_client_state = 0 as *mut scram_client_state;
    let mut buf: [libc::c_char; 18] = [0; 18];
    let mut rc: libc::c_int = 0;
    state = calloc(::std::mem::size_of::<scram_client_state>(), 1) as *mut scram_client_state;
    if state.is_null() {
        return GSASL_MALLOC_ERROR as libc::c_int;
    }
    (*state).plus = plus;
    (*state).hash = hash;
    rc = gsasl_nonce(buf.as_mut_ptr(), 18 as libc::c_int as size_t);
    if rc != GSASL_OK as libc::c_int {
        rpl_free(state as *mut libc::c_void);
        return rc;
    }
    rc = gsasl_base64_to(
        buf.as_mut_ptr(),
        18,
        &mut (*state).cf.client_nonce,
        0 as *mut size_t,
    );
    if rc != GSASL_OK as libc::c_int {
        rpl_free(state as *mut libc::c_void);
        return rc;
    }
    *mech_data = state as *mut libc::c_void;
    return GSASL_OK as libc::c_int;
}

pub(crate) unsafe fn _gsasl_scram_sha1_client_start(
    sctx: &Shared,
    mech_data: &mut Option<NonNull<()>>,
) -> libc::c_int {
    let mut ptr = mech_data
        .map(|ptr| ptr.as_ptr().cast())
        .unwrap_or_else(std::ptr::null_mut);

    let ret = scram_start(sctx, &mut ptr, 0 as libc::c_int != 0, GSASL_HASH_SHA1);

    *mech_data = NonNull::new(ptr.cast());

    return ret;
}

pub(crate) unsafe fn _gsasl_scram_sha1_plus_client_start(
    sctx: &Shared,
    mech_data: &mut Option<NonNull<()>>,
) -> libc::c_int {
    let mut ptr = mech_data
        .map(|ptr| ptr.as_ptr().cast())
        .unwrap_or_else(std::ptr::null_mut);

    let ret = scram_start(sctx, &mut ptr, 1 as libc::c_int != 0, GSASL_HASH_SHA1);

    *mech_data = NonNull::new(ptr.cast());

    return ret;
}

pub(crate) unsafe fn _gsasl_scram_sha256_client_start(
    sctx: &Shared,
    mech_data: &mut Option<NonNull<()>>,
) -> libc::c_int {
    let mut ptr = mech_data
        .map(|ptr| ptr.as_ptr().cast())
        .unwrap_or_else(std::ptr::null_mut);

    let ret = scram_start(sctx, &mut ptr, 0 as libc::c_int != 0, GSASL_HASH_SHA256);
    assert!(!ptr.is_null());
    *mech_data = NonNull::new(ptr.cast());

    return ret;
}

pub(crate) unsafe fn _gsasl_scram_sha256_plus_client_start(
    sctx: &Shared,
    mech_data: &mut Option<NonNull<()>>,
) -> libc::c_int {
    let mut ptr = mech_data
        .map(|ptr| ptr.as_ptr().cast())
        .unwrap_or_else(std::ptr::null_mut);

    let ret = scram_start(sctx, &mut ptr, 1 as libc::c_int != 0, GSASL_HASH_SHA256);

    *mech_data = NonNull::new(ptr.cast());

    return ret;
}

pub unsafe fn _gsasl_scram_client_step(
    sctx: &mut SessionData,
    mech_data: Option<NonNull<()>>,
    input: Option<&[u8]>,
    output: *mut *mut libc::c_char,
    output_len: *mut size_t,
) -> libc::c_int {
    let mech_data = mech_data.map(|ptr| ptr.as_ptr()).unwrap();

    let input_len = input.map(|i| i.len()).unwrap_or(0);
    let input: *const libc::c_char = input.map(|i| i.as_ptr().cast()).unwrap_or(std::ptr::null());

    let mut state: *mut scram_client_state = mech_data as *mut scram_client_state;
    let res: libc::c_int = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int;
    let mut rc: libc::c_int = 0;
    *output = 0 as *mut libc::c_char;
    *output_len = 0 as libc::c_int as size_t;
    match (*state).step {
        0 => {
            let mut p: *const libc::c_char = 0 as *const libc::c_char;
            p = gsasl_property_get(sctx, GSASL_CB_TLS_UNIQUE);
            if (*state).plus as libc::c_int != 0 && p.is_null() {
                return GSASL_NO_CB_TLS_UNIQUE as libc::c_int;
            }
            if !p.is_null() {
                rc = gsasl_base64_from(
                    p,
                    strlen(p),
                    &mut (*state).cbtlsunique,
                    &mut (*state).cbtlsuniquelen,
                );
                if rc != GSASL_OK as libc::c_int {
                    return rc;
                }
            }
            if (*state).plus {
                (*state).cf.cbflag = 'p' as i32 as libc::c_char;
                (*state).cf.cbname = strdup(b"tls-unique\x00" as *const u8 as *const libc::c_char)
            } else if (*state).cbtlsuniquelen > 0 {
                (*state).cf.cbflag = 'y' as i32 as libc::c_char
            } else {
                (*state).cf.cbflag = 'n' as i32 as libc::c_char
            }
            p = gsasl_property_get(sctx, GSASL_AUTHID);
            if p.is_null() {
                return GSASL_NO_AUTHID as libc::c_int;
            }
            rc = gsasl_saslprep(
                p,
                GSASL_ALLOW_UNASSIGNED,
                &mut (*state).cf.username,
                0 as *mut libc::c_int,
            );
            if rc != GSASL_OK as libc::c_int {
                return rc;
            }
            p = gsasl_property_get(sctx, GSASL_AUTHZID);
            if !p.is_null() {
                (*state).cf.authzid = strdup(p)
            }
            rc = scram_print_client_first(&mut (*state).cf, output);
            if rc == -(2 as libc::c_int) {
                return GSASL_MALLOC_ERROR as libc::c_int;
            } else {
                if rc != 0 as libc::c_int {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int;
                }
            }
            *output_len = strlen(*output);
            /* Point p to client-first-message-bare. */
            p = strchr(*output, ',' as i32);
            if p.is_null() {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int;
            }
            p = p.offset(1);
            p = strchr(p, ',' as i32);
            if p.is_null() {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int;
            }
            p = p.offset(1);
            /* Save "client-first-message-bare" for the next step. */
            (*state).cfmb = strdup(p);
            if (*state).cfmb.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int;
            }
            /* Prepare B64("cbind-input") for the next step. */
            if (*state).cf.cbflag as libc::c_int == 'p' as i32 {
                let len: size_t = (p.offset_from(*output))
                    .wrapping_add((*state).cbtlsuniquelen as isize)
                    as usize;
                let cbind_input: *mut libc::c_char = malloc(len) as *mut libc::c_char;
                if cbind_input.is_null() {
                    return GSASL_MALLOC_ERROR as libc::c_int;
                }
                memcpy(
                    cbind_input as *mut libc::c_void,
                    *output as *const libc::c_void,
                    p.offset_from(*output) as size_t,
                );
                memcpy(
                    cbind_input.offset(p.offset_from(*output)) as *mut libc::c_void,
                    (*state).cbtlsunique as *const libc::c_void,
                    (*state).cbtlsuniquelen,
                );
                rc = gsasl_base64_to(cbind_input, len, &mut (*state).cl.cbind, 0 as *mut size_t);
                rpl_free(cbind_input as *mut libc::c_void);
            } else {
                rc = gsasl_base64_to(
                    *output,
                    p.offset_from(*output) as libc::c_long as size_t,
                    &mut (*state).cl.cbind,
                    0 as *mut size_t,
                )
            }
            if rc != 0 as libc::c_int {
                return rc;
            }
            /* We are done. */
            (*state).step += 1;
            return GSASL_NEEDS_MORE as libc::c_int;
        }
        1 => {
            if scram_parse_server_first(input, input_len, &mut (*state).sf) < 0 as libc::c_int {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int;
            }
            if strlen((*state).sf.nonce) < strlen((*state).cf.client_nonce)
                || memcmp(
                    (*state).cf.client_nonce as *const libc::c_void,
                    (*state).sf.nonce as *const libc::c_void,
                    strlen((*state).cf.client_nonce),
                ) != 0 as libc::c_int
            {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int;
            }
            (*state).cl.nonce = strdup((*state).sf.nonce);
            if (*state).cl.nonce.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int;
            }
            /* Save salt/iter as properties, so that client callback can
            access them. */
            let mut str: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut n: libc::c_int = 0;
            n = asprintf(
                &mut str as *mut *mut libc::c_char,
                b"%zu\x00" as *const u8 as *const libc::c_char,
                (*state).sf.iter,
            );
            if n < 0 as libc::c_int || str.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int;
            }
            rc = gsasl_property_set(sctx, GSASL_SCRAM_ITER, str);
            rpl_free(str as *mut libc::c_void);
            if rc != GSASL_OK as libc::c_int {
                return rc;
            }
            rc = gsasl_property_set(sctx, GSASL_SCRAM_SALT, (*state).sf.salt);
            if rc != GSASL_OK as libc::c_int {
                return rc;
            }
            /* Generate ClientProof. */
            let mut saltedpassword: [libc::c_char; 32] = [0; 32];
            let mut clientkey: [libc::c_char; 32] = [0; 32];
            let mut serverkey: [libc::c_char; 32] = [0; 32];
            let mut storedkey: [libc::c_char; 32] = [0; 32];
            let mut p_0: *const libc::c_char = 0 as *const libc::c_char;
            /* Get SaltedPassword. */
            p_0 = gsasl_property_get(sctx, GSASL_SCRAM_SALTED_PASSWORD);
            if !p_0.is_null()
                && strlen(p_0) == (2 as size_t).wrapping_mul(gsasl_hash_length((*state).hash))
                && _gsasl_hex_p(p_0) as libc::c_int != 0
            {
                _gsasl_hex_decode(p_0, saltedpassword.as_mut_ptr());
                rc = gsasl_scram_secrets_from_salted_password(
                    (*state).hash,
                    saltedpassword.as_mut_ptr(),
                    clientkey.as_mut_ptr(),
                    serverkey.as_mut_ptr(),
                    storedkey.as_mut_ptr(),
                );
                if rc != 0 as libc::c_int {
                    return rc;
                }
            } else {
                p_0 = gsasl_property_get(sctx, GSASL_PASSWORD);
                if !p_0.is_null() {
                    let mut salt: *mut libc::c_char = 0 as *mut libc::c_char;
                    let mut saltlen: size_t = 0;
                    rc = gsasl_base64_from(
                        (*state).sf.salt,
                        strlen((*state).sf.salt),
                        &mut salt,
                        &mut saltlen,
                    );
                    if rc != 0 as libc::c_int {
                        return rc;
                    }
                    rc = gsasl_scram_secrets_from_password(
                        (*state).hash,
                        p_0,
                        (*state).sf.iter as libc::c_uint,
                        salt,
                        saltlen,
                        saltedpassword.as_mut_ptr(),
                        clientkey.as_mut_ptr(),
                        serverkey.as_mut_ptr(),
                        storedkey.as_mut_ptr(),
                    );
                    if rc != 0 as libc::c_int {
                        return rc;
                    }
                    rc = set_saltedpassword(sctx, (*state).hash, saltedpassword.as_mut_ptr());
                    if rc != GSASL_OK as libc::c_int {
                        return rc;
                    }
                    gsasl_free(salt as *mut libc::c_void);
                } else {
                    return GSASL_NO_PASSWORD as libc::c_int;
                }
            }
            /* Get client-final-message-without-proof. */
            let mut cfmwp: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut n_0: libc::c_int = 0;
            (*state).cl.proof = strdup(b"p\x00" as *const u8 as *const libc::c_char);
            rc = scram_print_client_final(&mut (*state).cl, &mut cfmwp);
            if rc != 0 as libc::c_int {
                return GSASL_MALLOC_ERROR as libc::c_int;
            }
            rpl_free((*state).cl.proof as *mut libc::c_void);
            /* Compute AuthMessage */
            n_0 = asprintf(
                &mut (*state).authmessage as *mut *mut libc::c_char,
                b"%s,%.*s,%.*s\x00" as *const u8 as *const libc::c_char,
                (*state).cfmb,
                input_len as libc::c_int,
                input,
                strlen(cfmwp).wrapping_sub(4) as libc::c_int,
                cfmwp,
            );
            rpl_free(cfmwp as *mut libc::c_void);
            if n_0 <= 0 as libc::c_int || (*state).authmessage.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int;
            }
            let mut clientsignature: [libc::c_char; 32] = [0; 32];
            let mut clientproof: [libc::c_char; 32] = [0; 32];
            /* ClientSignature := HMAC(StoredKey, AuthMessage) */
            rc = _gsasl_hmac(
                (*state).hash,
                storedkey.as_mut_ptr(),
                gsasl_hash_length((*state).hash),
                (*state).authmessage,
                strlen((*state).authmessage),
                clientsignature.as_mut_ptr(),
            );
            if rc != 0 as libc::c_int {
                return rc;
            }
            /* ClientProof := ClientKey XOR ClientSignature */
            memcpy(
                clientproof.as_mut_ptr() as *mut libc::c_void,
                clientkey.as_mut_ptr() as *const libc::c_void,
                gsasl_hash_length((*state).hash),
            );
            memxor(
                clientproof.as_mut_ptr() as *mut libc::c_void,
                clientsignature.as_mut_ptr() as *const libc::c_void,
                gsasl_hash_length((*state).hash),
            );
            rc = gsasl_base64_to(
                clientproof.as_mut_ptr(),
                gsasl_hash_length((*state).hash),
                &mut (*state).cl.proof,
                0 as *mut size_t,
            );
            if rc != 0 as libc::c_int {
                return rc;
            }
            /* Generate ServerSignature, for comparison in next step. */
            let mut serversignature: [libc::c_char; 32] = [0; 32];
            /* ServerSignature := HMAC(ServerKey, AuthMessage) */
            rc = _gsasl_hmac(
                (*state).hash,
                serverkey.as_mut_ptr(),
                gsasl_hash_length((*state).hash),
                (*state).authmessage,
                strlen((*state).authmessage),
                serversignature.as_mut_ptr(),
            );
            if rc != 0 as libc::c_int {
                return rc;
            }
            rc = gsasl_base64_to(
                serversignature.as_mut_ptr(),
                gsasl_hash_length((*state).hash),
                &mut (*state).serversignature,
                0 as *mut size_t,
            );
            if rc != 0 as libc::c_int {
                return rc;
            }
            rc = scram_print_client_final(&mut (*state).cl, output);
            if rc != 0 as libc::c_int {
                return GSASL_MALLOC_ERROR as libc::c_int;
            }
            *output_len = strlen(*output);
            (*state).step += 1;
            return GSASL_NEEDS_MORE as libc::c_int;
        }
        2 => {
            if scram_parse_server_final(input, input_len, &mut (*state).sl) < 0 as libc::c_int {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int;
            }
            if strcmp((*state).sl.verifier, (*state).serversignature) != 0 as libc::c_int {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int;
            }
            (*state).step += 1;
            return GSASL_OK as libc::c_int;
        }
        _ => {}
    }
    return res;
}

pub unsafe fn _gsasl_scram_client_finish(mech_data: Option<NonNull<()>>) {
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);

    let state: *mut scram_client_state = mech_data as *mut scram_client_state;
    if state.is_null() {
        return;
    }
    rpl_free((*state).cfmb as *mut libc::c_void);
    rpl_free((*state).serversignature as *mut libc::c_void);
    rpl_free((*state).authmessage as *mut libc::c_void);
    rpl_free((*state).cbtlsunique as *mut libc::c_void);
    scram_free_client_first(&mut (*state).cf);
    scram_free_server_first(&mut (*state).sf);
    scram_free_client_final(&mut (*state).cl);
    scram_free_server_final(&mut (*state).sl);
    rpl_free(state as *mut libc::c_void);
}
