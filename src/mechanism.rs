//! Mechanism traits *only available with feature `unstable_custom_mechanism`*
//!
//!
use crate::error::SessionError::NoSecurityLayer;
use core2::io::Write;

#[cfg(any(doc, feature = "unstable_custom_mechanism"))]
pub use crate::context::{Demand, DemandReply, EmptyProvider, Provider, ProviderExt, ThisProvider};
#[cfg(any(doc, feature = "unstable_custom_mechanism"))]
pub use crate::error::MechanismErrorKind;
#[allow(unused_imports)]
pub use crate::error::{MechanismError, SessionError};
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
    /// - [`State::Finished`] must only be returned if no further calls to `step` are expected in
    ///   **any case**. If another `step` may occur on e.g. an error [`State::Running`] **MUST**
    ///   be returned.
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
    ///   Most importantly, a mechanisms **MUST NOT** return `Ok(State::Running)` as this
    ///   can result in an infinite loop if both sides of the authentication think the other
    ///   should go first.
    /// - In case an `Err(InputDataRequired)` is returned a second call to step *with* data
    ///   **SHOULD** continue the authentication exchange as if the invalid call never happened.
    ///   This means if input data is required but was not provided the internal state **SHOULD**
    ///   remain the same and not become invalid.
    ///
    /// - The server side implemented of a mechanism **MUST** call [`MechanismData::validate`]
    ///   *exactly once* in an authentication exchange, unless a protocol error is encountered.
    ///   (i.e. the call has to have happened before `Ok(State::Finished(_))` is returned)
    ///
    ///   `validate` is passed a `Provider` giving user callbacks access to property values from
    ///   this exchange to base authentication decisions on. This Provider **MUST** always
    ///   provide the same set of properties; if a property may be absent in some circumstances it
    ///   **MUST** specify and return a special 'absent' value in those cases.
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<State, SessionError>;

    // TODO: Document the problems with SASL security layers before release
    /// Encode given data for an established SASL security layer
    ///
    /// This operation is also often called `wrap`. If a security layer has been established this
    /// method protects input data using said security layer and writes it into the provided writer.
    ///
    /// If no security layer has been installed this method MUST return
    /// `Err(`[`SessionError::NoSecurityLayer`]`).
    ///
    /// A call to this function returns the number of input bytes that were successfully
    /// protected and written into the given writer. As this protection may add overhead,
    /// compression, … the number of bytes **written** will differ from the returned **read** amount
    /// of bytes. If a caller requires the number of bytes written it is their obligation to use
    /// a tracking writer.
    ///
    /// This method will not flush the provided writer.
    ///
    /// A single call to encode SHOULD only protect one security layer 'frame' of data, e.g. with
    /// GSS-API call `wrap` only once.  However it MAY call `Write::write` multiple times, and
    /// SHOULD return `Ok(0)` if any of those calls return `Ok(0)`.
    fn encode(&mut self, _input: &[u8], _writer: &mut dyn Write) -> Result<usize, SessionError> {
        Err(NoSecurityLayer)
    }

    /// Decode data from an established SASL security layer
    ///
    /// This operation is also often called `unwrap`. If a security layer has been established this
    /// method unprotects input data from said security layer and writes it into the provided
    /// writer.
    ///
    /// If no security layer has been installed this method MUST return
    /// `Err(`[`SessionError::NoSecurityLayer`]`)`.  If there is not enough input data to
    /// successfully unprotect this method MUST return `Err(`[`SessionError::InputDataRequired`]`)`
    ///
    /// A call to this function returns the number of protected input bytes that were successfully
    /// unprotected and written into the given writer.
    ///
    /// This method will not flush the provided writer.
    ///
    /// Similarly to `encode` a single call to decode SHOULD only unprotect a single `frame` of
    /// data, e.g. with GSS-API call `unwrap` only once.  However it MAY call `Write::write`
    /// multiple times, and SHOULD return `OK(0)` if any of those calls return `Ok(0)`.
    fn decode(&mut self, _input: &[u8], _writer: &mut dyn Write) -> Result<usize, SessionError> {
        Err(NoSecurityLayer)
    }

    /// Returns `true` if a security layer is installed at the moment, otherwise returns `false`.
    fn has_security_layer(&self) -> bool {
        false
    }
}

// TODO(?): Proper generic version of the Authentication trait with defined Error types?
//          Would make rsasl more useful in the no-framework/statically defined use-case.
//          Probably a thing to be explored later.

#[cfg(test)]
mod test {
    static_assertions::assert_obj_safe!(super::Authentication);
}
