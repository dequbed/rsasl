//! Mechanism traits *only available with feature `unstable_custom_mechanism`*
//!
//!
use crate::error::SessionError;
use crate::error::SessionError::NoSecurityLayer;
use std::io::Write;

pub use crate::context::{Demand, DemandReply, Provider, ThisProvider};
pub use crate::error::{MechanismError, MechanismErrorKind};
pub use crate::session::{MechanismData, StepResult};

/// Trait implemented to be one party in an authentication exchange
///
/// This trait is used irrespectively of the side of the authentication exchange, i.e. it gets
/// used both on the client side and on the server side. If the Mechanism being implemented is not
/// symmetric but has different behaviour depending on the side an Implementation should define two
/// distinct types representing the client and server side:
///
/// and register the two types separately
pub trait Authentication {
    /// Do a single step of authentication with the other party
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> StepResult;

    // TODO: Document the problems with SASL security layers before release
    // TODO: Split Authentication & Security Layer stuff?
    // TODO: `fn is_security_layer_installed(&self) -> bool`?
    fn encode(&mut self, _input: &[u8], _writer: &mut dyn Write) -> Result<usize, SessionError> {
        Err(NoSecurityLayer)
    }
    fn decode(&mut self, _input: &[u8], _writer: &mut dyn Write) -> Result<usize, SessionError> {
        Err(NoSecurityLayer)
    }
}

// TODO(?): Proper generic version of the Authentication trait with defined Error types?
//          Would make rsasl more useful in the no-framework/statically defined use-case.
//          Probably a thing to be explored later.
