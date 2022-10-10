//! X-RSASLTEST mechanism
//!
//! This mechanism tests for a number of handling edge-cases in protocol implementations. It's a
//! multi-step mechanism and does not rely on further input by an user.

use crate::mechanism::{Authentication, MechanismData};
use crate::prelude::*;
use crate::registry::{Mechanism, Side};
use acid_io::Write;

/// X-RSASLTEST implementation
///
/// # Steps
///
/// Below is a description of all steps of this mechanism in order. Steps are numbered over both
/// sides together; the client's first data is step 1, the server's first data is step 2, etc.
/// This means the *second* call to `step` on the Client side is step *three* in the following
/// description.
///
/// ## Step 1
///
/// The initiating side generates the "initial nonce", 32 bytes of random data.
/// If the '-PLUS' variant is used, the name of the channel bindings to use are sent in this step
/// too.
///
/// Message format in RFC 5234 ABNF:
///
/// ```abnf
/// HEXDIGIT    = %x30-39 / %x41-46 / %61-66        ;; Any of either 0-9, A-Z or a-z
/// cbname      = 1* (ALPHA / DIGIT / "." / "-")    ;; channel binding name
/// gs2-cb-flag = ("p=" cbname / "y" / "n" )        ;;
///               ;; GS2 channel binding (CB) flag
///               ;; "p" -> client supports and used CB (name of used cb in set as `cbname`)
///               ;; "n" -> client does not support CB
///               ;; "y" -> client supports CB, thinks the server does not
///
/// initial-nonce = 64HEXDIGIT                 ;; Nonce has 32 bytes, thus 64 hex chars
/// initial-msg = gs2-cb-flag "," "r=" initial-nonce
/// ```
///
/// ## Step 2
///
/// An 64-byte "shared nonce" is generated, consisting of the 32 bytes received from Step 1, with
/// an additional 32 byte **appended** to it.
/// A reponse token is set to "Server" if the current side is the server (i.e. the client-first
/// variant was used) or "Client" otherwise.
///
/// Message format, rules from Step 1 are implied
/// ```abnf
/// responder-nonce = 64HEXDIGIT
/// shared-nonce = "r=" initial-nonce responder-nonce
/// second-msg = shared-nonce
/// ```
///
/// ## Step 3
///
/// ```abnf
/// initiator-final-message-without-proof = channel-binding "," shared-nonce
/// third-msg = initiator-final-message-without-proof "," proof
/// ```
///
/// ## Step 4
///
/// ```abnf
/// responder-error = "e=" responder-error-value
/// responder-error-value = "mismatched sides"
/// verifier = "v=" 64HEXDIGIT
/// final-message = responder-error / verifier
/// ```
///
/// client-first/server-first depends on which side performs step 1.
#[allow(unused)]
pub struct RSaslTest {
    state: RsaslState,
}
impl RSaslTest {
    #[allow(clippy::unnecessary_wraps)]
    pub fn client(
        _config: &SASLConfig,
        _offered: &[&Mechname],
    ) -> Result<Box<dyn Authentication>, SASLError> {
        Ok(Box::new(Self {
            state: RsaslState::New,
        }))
    }
    #[allow(clippy::unnecessary_wraps)]
    pub fn server(_config: &SASLConfig) -> Result<Box<dyn Authentication>, SASLError> {
        Ok(Box::new(Self {
            state: RsaslState::New,
        }))
    }
}

#[allow(unused)]
enum RsaslState {
    New,
    First,
    Second,
    Third,
    Fourth,
}

impl Authentication for RSaslTest {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<State, SessionError> {
        let _ = (session, input, writer);
        todo!()
    }
}

pub static RSASLTEST_CF: Mechanism = Mechanism {
    mechanism: Mechname::const_new(b"X-RSASLTEST-CF"),
    priority: 0,
    client: Some(RSaslTest::client),
    server: Some(RSaslTest::server),
    first: Side::Client,
};
pub static RSASLTEST_SF: Mechanism = Mechanism {
    mechanism: Mechname::const_new(b"X-RSASLTEST-SF"),
    priority: 0,
    client: Some(RSaslTest::client),
    server: Some(RSaslTest::server),
    first: Side::Client,
};
