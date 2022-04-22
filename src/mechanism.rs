use crate::error::SessionError;
use crate::error::SessionError::NoSecurityLayer;
use crate::session::{MechanismData, Step, StepResult};
use std::io::Write;

/// Trait implemented to be one party in an authentication exchange
///
/// This trait is used irrespectively of the side of the authentication exchange, i.e. it gets
/// used both on the client side and on the server side. If the Mechanism being implemented is not
/// symmetric but has different behaviour depending on the side an Implementation should define two
/// distinct types representing the client and server side:
///
/// ```rust
/// # use std::io::Write;
/// # use rsasl::mechanism::Authentication;
/// # use rsasl::session::{MechanismData, StepResult};
/// // Data required for both sides
/// struct Common {
///     step: usize,
///     hash: [u8; 64],
/// }
/// #[repr(transparent)]
/// pub struct Client(Common);
/// #[repr(transparent)]
/// pub struct Server(Common);
///
/// impl Authentication for Client {
///     fn step(&mut self, session: &mut MechanismData, input: Option<&[u8]>, writer: &mut dyn Write) -> StepResult {
///         match self.0.step {
///             0 => { }
///             _ => { }
///         }
///         # unimplemented!()
///     }
/// }
/// impl Authentication for Server {
///     fn step(&mut self, session: &mut MechanismData, input: Option<&[u8]>, writer: &mut dyn Write) -> StepResult {
///         # unimplemented!()
///     }
/// }
/// ```
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
    fn encode(&mut self, _input: &[u8]) -> Result<Box<[u8]>, SessionError> {
        Err(NoSecurityLayer)
    }
    fn decode(&mut self, _input: &[u8]) -> Result<Box<[u8]>, SessionError> {
        Err(NoSecurityLayer)
    }
}

// TODO(?): Proper generic version of the Authentication trait with defined Error types?
//          Would make rsasl more useful in the no-framework/statically defined use-case.
//          Probably a thing to be explored later.