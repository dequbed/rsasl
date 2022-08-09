//! Mechanism traits *only available with feature `unstable_custom_mechanism`*
//!
//!
use crate::error::SessionError::NoSecurityLayer;
use std::io::Write;

pub use crate::context::{Demand, DemandReply, Provider, ProviderExt, ThisProvider};
pub use crate::error::{MechanismError, MechanismErrorKind, SessionError};
pub use crate::session::{MechanismData, State};

/// Trait implemented to be one party in an authentication exchange
///
/// This trait is used irrespectively of the side of the authentication exchange, i.e. it gets
/// used both on the client side and on the server side. If the Mechanism being implemented is not
/// symmetric but has different behaviour depending on the side an Implementation should define two
/// distinct types representing the client and server side:
///
/// and register the two types separately
pub trait Authentication: Send + Sync {
    /// Do a single step of authentication with the other party
    ///
    /// rsasl has a few assumptions about the behaviour of any implementor of this trait:
    ///
    /// - The two fields of the returned tuple return the **new state** of the mechanism and the
    ///   **amount of data written** into the writer.
    /// - [`State::Finished`] must only be returned if no further calls to `step` are expected in
    ///   **any case**. If another `step` may occur on e.g. an error [`State::Running`] **MUST**
    ///   be returned.
    /// - The written amount **MUST** be returned as `Some(0)` if an empty response needs to be
    ///   sent to the other side. `None` can only be returned if *no* response shall be sent to
    ///   the other party.
    /// - Calling `step` after the last call returned `State::Finished` is undefined behaviour.
    ///   An implementation is free to write garbage data into the writer, return an error or panic.
    ///
    /// - If the current/local side of the authentication is going **first** a call to `step` with
    ///   an input of `None` will generate the first batch of data.
    /// - When a mechanism is called with no input or an empty input when this was not expected, a
    ///   mechanism **MUST** return an Error. [`SessionError::InputDataRequired`] is a safe
    ///   default here, but if this behaviour results in e.g. the server not being
    ///   mutually authenticated other [`SessionError`]s or [`MechanismError`]s can be appropriate.
    ///
    ///   Most importantly, a mechanisms **MUST NOT** return `Ok((State::Running, None))` as this
    ///   can result in an infinite loop if both sides of the authentication think the other
    ///   should go first.
    /// - Incase an `Err(InputDataRequired)` is returned a second call to step *with* data
    ///   **SHOULD** continue the authentication exchange as if the invalid call never happened.
    ///   This means if input data is required but was not provided the internal state **SHOULD**
    ///   remain the same and not become invalid.
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<(State, Option<usize>), SessionError>;

    // TODO: Document the problems with SASL security layers before release
    // TODO: Split Authentication & Security Layer stuff?
    // TODO: `fn is_security_layer_installed(&self) -> bool`?
    fn encode(&mut self, _input: &[u8], _writer: &mut dyn Write) -> Result<usize, SessionError> {
        Err(NoSecurityLayer)
    }
    fn decode(&mut self, _input: &[u8], _writer: &mut dyn Write) -> Result<usize, SessionError> {
        Err(NoSecurityLayer)
    }
    fn has_security_layer(&self) -> bool {
        false
    }
}

// TODO(?): Proper generic version of the Authentication trait with defined Error types?
//          Would make rsasl more useful in the no-framework/statically defined use-case.
//          Probably a thing to be explored later.
