use std::error::Error;
use crate::alloc::boxed::Box;

use thiserror::Error;

use crate::callback::CallbackError;
use crate::validate::ValidationError;
use core::fmt;

static UNKNOWN_ERROR: &'static str = "The given error code is unknown to gsasl";

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

    #[cfg(feature = "gsasl")]
    #[error(transparent)]
    Gsasl(#[from] gsasl::Gsasl),
}

#[cfg(feature = "gsasl")]
mod gsasl {
    use thiserror::Error;
    use std::ffi::CStr;
    use std::fmt;
    use crate::error::UNKNOWN_ERROR;
    use super::{MechanismError, MechanismErrorKind};
    use crate::gsasl::error::{gsasl_strerror, gsasl_strerror_name};

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Error)]
    pub struct Gsasl(pub libc::c_uint);
    impl fmt::Debug for Gsasl {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(rsasl_errname_to_str(self.0 as u32).unwrap_or("UNKNOWN_ERROR"))
        }
    }
    impl fmt::Display for Gsasl {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(rsasl_err_to_str(self.0).unwrap_or("an unknown error was encountered"))
        }
    }
    impl MechanismError for Gsasl {
        fn kind(&self) -> MechanismErrorKind {
            // TODO: match self and return proper type
            MechanismErrorKind::Protocol
        }
    }

    /// Convert an error code to a human readable description of that error
    fn rsasl_err_to_str(err: libc::c_uint) -> Option<&'static str> {
        // gsasl returns the normal zero-terminated string
        let cstr = unsafe {
            let ptr = gsasl_strerror(err as libc::c_int);
            if ptr.is_null() {
                return None;
            }

            CStr::from_ptr(ptr)
        };
        // Yes, this could potentially fail. But we're talking about an array of static, compiled-in
        // strings here. If they aren't UTF-8 that's clearly a bug.
        Some(
            cstr.to_str()
                .expect("GSASL library contains bad UTF-8 error descriptions"),
        )
    }

    /// Convert an error code to a human readable description of that error
    #[deprecated(since = "1.1.0", note = "Use rsasl_err_to_str as replacement")]
    fn gsasl_err_to_str(err: libc::c_uint) -> &'static str {
        gsasl_err_to_str_internal(err)
    }

    fn gsasl_err_to_str_internal(err: libc::c_uint) -> &'static str {
        // gsasl returns the normal zero-terminated string
        let cstr = unsafe {
            let ptr = gsasl_strerror(err as libc::c_int);
            if ptr.is_null() {
                return UNKNOWN_ERROR;
            }

            CStr::from_ptr(ptr)
        };
        // Yes, this could potentially fail. But we're talking about an array of static, compiled-in
        // strings here. If they aren't UTF-8 that's clearly a bug.
        cstr.to_str()
            .expect("GSASL library contains bad UTF-8 error descriptions")
    }

    /// Convert an error type to the human readable name of that error.
    /// i.e. rsasl_errname_to_str(GSASL_OK) -> "GSASL_OK". Returns `None` when an invalid libc::c_int is
    /// passed.
    fn rsasl_errname_to_str(err: libc::c_uint) -> Option<&'static str> {
        // gsasl returns the normal zero-terminated string
        let cstr = unsafe {
            let ptr = gsasl_strerror_name(err as libc::c_int);
            if ptr.is_null() {
                return None;
            }

            CStr::from_ptr(ptr)
        };
        // Yes, this could potentially fail. But we're talking about an array of static, compiled-in
        // strings here. If they aren't UTF-8 that's clearly a bug.
        Some(
            cstr.to_str()
                .expect("GSASL library contains bad UTF-8 error descriptions"),
        )
    }

    /// Convert an error code to the human readable name of that error.
    /// i.e. gsasl_errname_to_str(GSASL_OK) -> "GSASL_OK"
    #[deprecated]
    fn gsasl_errname_to_str(err: libc::c_uint) -> &'static str {
        // gsasl returns the normal zero-terminated string
        let cstr = unsafe {
            let ptr = gsasl_strerror_name(err as libc::c_int);
            if ptr.is_null() {
                return UNKNOWN_ERROR;
            }

            CStr::from_ptr(ptr)
        };
        // Yes, this could potentially fail. But we're talking about an array of static, compiled-in
        // strings here. If they aren't UTF-8 that's clearly a bug.
        cstr.to_str()
            .expect("GSASL library contians bad UTF-8 error names")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::gsasl::consts::*;

        #[test]
        fn errname_to_str_valid() {
            assert_eq!(rsasl_errname_to_str(GSASL_OK), Some("GSASL_OK"));
            assert_eq!(
                rsasl_errname_to_str(GSASL_NEEDS_MORE),
                Some("GSASL_NEEDS_MORE")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_UNKNOWN_MECHANISM),
                Some("GSASL_UNKNOWN_MECHANISM")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_MECHANISM_CALLED_TOO_MANY_TIMES),
                Some("GSASL_MECHANISM_CALLED_TOO_MANY_TIMES")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_MALLOC_ERROR),
                Some("GSASL_MALLOC_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_BASE64_ERROR),
                Some("GSASL_BASE64_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_CRYPTO_ERROR),
                Some("GSASL_CRYPTO_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_SASLPREP_ERROR),
                Some("GSASL_SASLPREP_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_MECHANISM_PARSE_ERROR),
                Some("GSASL_MECHANISM_PARSE_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_AUTHENTICATION_ERROR),
                Some("GSASL_AUTHENTICATION_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_INTEGRITY_ERROR),
                Some("GSASL_INTEGRITY_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_NO_CLIENT_CODE),
                Some("GSASL_NO_CLIENT_CODE")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_NO_SERVER_CODE),
                Some("GSASL_NO_SERVER_CODE")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_NO_CALLBACK),
                Some("GSASL_NO_CALLBACK")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_NO_ANONYMOUS_TOKEN),
                Some("GSASL_NO_ANONYMOUS_TOKEN")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_NO_AUTHID),
                Some("GSASL_NO_AUTHID")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_NO_AUTHZID),
                Some("GSASL_NO_AUTHZID")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_NO_PASSWORD),
                Some("GSASL_NO_PASSWORD")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_NO_PASSCODE),
                Some("GSASL_NO_PASSCODE")
            );
            assert_eq!(rsasl_errname_to_str(GSASL_NO_PIN), Some("GSASL_NO_PIN"));
            assert_eq!(
                rsasl_errname_to_str(GSASL_NO_SERVICE),
                Some("GSASL_NO_SERVICE")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_NO_HOSTNAME),
                Some("GSASL_NO_HOSTNAME")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_NO_CB_TLS_UNIQUE),
                Some("GSASL_NO_CB_TLS_UNIQUE")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_NO_SAML20_IDP_IDENTIFIER),
                Some("GSASL_NO_SAML20_IDP_IDENTIFIER")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_NO_SAML20_REDIRECT_URL),
                Some("GSASL_NO_SAML20_REDIRECT_URL")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_NO_OPENID20_REDIRECT_URL),
                Some("GSASL_NO_OPENID20_REDIRECT_URL")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_GSSAPI_RELEASE_BUFFER_ERROR),
                Some("GSASL_GSSAPI_RELEASE_BUFFER_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_GSSAPI_IMPORT_NAME_ERROR),
                Some("GSASL_GSSAPI_IMPORT_NAME_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR),
                Some("GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR),
                Some("GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_GSSAPI_UNWRAP_ERROR),
                Some("GSASL_GSSAPI_UNWRAP_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_GSSAPI_WRAP_ERROR),
                Some("GSASL_GSSAPI_WRAP_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_GSSAPI_ACQUIRE_CRED_ERROR),
                Some("GSASL_GSSAPI_ACQUIRE_CRED_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_GSSAPI_DISPLAY_NAME_ERROR),
                Some("GSASL_GSSAPI_DISPLAY_NAME_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR),
                Some("GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE),
                Some("GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_SECURID_SERVER_NEED_NEW_PIN),
                Some("GSASL_SECURID_SERVER_NEED_NEW_PIN")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR),
                Some("GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR),
                Some("GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR),
                Some("GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR),
                Some("GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR")
            );
            assert_eq!(
                rsasl_errname_to_str(GSASL_GSSAPI_RELEASE_OID_SET_ERROR),
                Some("GSASL_GSSAPI_RELEASE_OID_SET_ERROR")
            );
        }

        #[test]
        fn errname_to_str_invalid() {
            assert_eq!(rsasl_errname_to_str(u32::MAX), None);
            assert_eq!(
                rsasl_errname_to_str(GSASL_NO_OPENID20_REDIRECT_URL as libc::c_uint + 1),
                None
            );
        }
    }
}
#[cfg(feature = "gsasl")]
pub use gsasl::Gsasl;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_auto_traits() {
        static_assertions::assert_impl_all!(SessionError: Send, Sync);
    }

}
