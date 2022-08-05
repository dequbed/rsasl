use crate::alloc::boxed::Box;
use std::error::Error;

use thiserror::Error;

use crate::callback::CallbackError;
use crate::validate::ValidationError;
use core::fmt;

/// Different high-level kinds of errors that can happen in mechanisms
pub enum MechanismErrorKind {
    /// Parsing failed for the given reason (syntactical error)
    Parse,

    /// The messages where syntactically valid but a semantical error occurred during handling
    Protocol,

    /// While the exchange did complete correctly, the authentication itself failed for some
    /// reason or another.
    Outcome,
}

/// Errors specific to a certain mechanism
pub trait MechanismError: fmt::Debug + fmt::Display + Send + Sync + std::error::Error {
    fn kind(&self) -> MechanismErrorKind;
}

#[derive(Debug, Error)]
/// Error type returned when stepping an established `Session`
///
///
pub enum SessionError {
    #[error("IO error occurred")]
    Io {
        #[from]
        source: std::io::Error,
    },

    #[cfg(feature = "provider_base64")]
    #[error("base64 wrapping failed")]
    Base64 {
        #[from]
        source: base64::DecodeError,
    },

    #[error("no security layer is installed")]
    NoSecurityLayer,

    #[error("input data was required but not provided")]
    // Common Mechanism Errors:
    /// Mechanism was called without input data when requiring some
    InputDataRequired,

    #[error("step was called after mechanism finished")]
    MechanismDone,

    #[error("internal mechanism error: {0}")]
    MechanismError(Box<dyn MechanismError>),

    #[error("callback error")]
    CallbackError(
        #[from]
        #[source]
        CallbackError,
    ),

    #[error("validation error")]
    ValidationError(
        #[from]
        #[source]
        ValidationError,
    ),

    #[error(transparent)]
    Boxed(#[from] Box<dyn Error + Send + Sync>),

    #[error("callback did not validate the authentication exchange")]
    NoValidate,

    #[error("the server failed mutual authentication")]
    /// This error indicates that the server failed to authenticate itself to a client
    ///
    /// This is most of the time **a very bad thing**. It means that the server failed to show that
    /// it has access to the clients password *and let them in anyway*. While this may be okay in
    /// a few select circumstances this error should not be ignored lightly.
    ///
    /// Only mechanisms that perform mutual authentication can return this error, and it will
    /// only ever be returned on the client side of an authentication.
    MutualAuthenticationFailed,

    #[error("channel binding data for '{0}' is required")]
    MissingChannelBindingData(String),

    #[cfg(feature = "gsasl")]
    #[error(transparent)]
    Gsasl(Gsasl),
}

impl SessionError {
    pub fn input_required() -> Self {
        Self::InputDataRequired
    }

    pub fn is_mechanism_error(&self) -> bool {
        match self {
            Self::MechanismError(_) => true,
            _ => false,
        }
    }

    pub fn is_missing_prop(&self) -> bool {
        match self {
            Self::CallbackError(CallbackError::NoCallback(_)) => true,
            _ => false,
        }
    }
}

impl<T: MechanismError + 'static> From<T> for SessionError {
    fn from(e: T) -> Self {
        Self::MechanismError(Box::new(e))
    }
}

#[derive(Debug, Error)]
/// The error type for rsasl errors originating from [`SASLClient`] or [`SASLServer`]
///
/// This is one of two error types a protocol implementation needs to be aware of, the other
/// being [`SessionError`].
///
/// `SASLError` is returned when trying to establish a new `Session` from e.g. a list of offered
/// mechanisms.
pub enum SASLError {
    #[error("no shared mechanism found")]
    /// No mechanism from the offered list is available.
    ///
    /// This error may occur even if the mechanism is implemented by rsasl, as an user may have
    /// filtered the otherwise shared mechanisms.
    NoSharedMechanism,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_auto_traits() {
        static_assertions::assert_impl_all!(SessionError: Send, Sync);
    }
}
