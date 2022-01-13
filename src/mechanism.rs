use std::io::Write;
use crate::{Mechname, SASL, SASLError};
use crate::SASLError::NoSecurityLayer;
use crate::session::{SessionData, StepResult};

pub trait MechanismBuilder: Sync + Send {
    fn init(&self) {}
    fn start(&self, sasl: &SASL) -> Result<MechanismInstance, SASLError>;
}

pub struct MechanismInstance {
    pub name: &'static Mechname,
    pub(crate) inner: Box<dyn Authentication>,
}

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
/// # use rsasl::session::{SessionData, StepResult};
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
///     fn step(&mut self, session: &mut SessionData, input: Option<&[u8]>, writer: &mut dyn Write) -> StepResult {
///         match self.0.step {
///             0 => { }
///             _ => { }
///         }
///         # unimplemented!()
///     }
/// }
/// impl Authentication for Server {
///     fn step(&mut self, session: &mut SessionData, input: Option<&[u8]>, writer: &mut dyn Write) -> StepResult {
///         # unimplemented!()
///     }
/// }
/// ```
///
/// And register the two types separately
pub trait Authentication {
    /// Do a single step of authentication with the other party
    fn step(&mut self,
            session: &mut SessionData,
            input: Option<&[u8]>,
            writer: &mut dyn Write
    ) -> StepResult;

    fn encode(&mut self, input: &[u8]) -> Result<Box<[u8]>, SASLError> {
        Err(NoSecurityLayer)
    }
    fn decode(&mut self, input: &[u8]) -> Result<Box<[u8]>, SASLError> {
        Err(NoSecurityLayer)
    }
}