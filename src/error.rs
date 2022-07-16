use crate::gsasl::error::{gsasl_strerror, gsasl_strerror_name};

use crate::Mechname;
use thiserror::Error;

use crate::callback::CallbackError;
use crate::mechname::MechanismNameError;
use crate::validate::ValidationError;
use std::ffi::CStr;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};

// TODO: Error types:
// - Setup error. Bad Mechanism, no shared mechanism, mechanism failed to start.
//      * `SetupError`?
// - Session error. Stepping Mechanism broke, I/O error in output writer, requirements not delivered
//      * Callback error should be handled specifically?
//      * Includes Authentication error. Mechanism stepped to completion, authentication *failed*.

pub type Result<T> = std::result::Result<T, SASLError>;

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
pub trait MechanismError: Debug + Display + Send + Sync + std::error::Error {
    fn kind(&self) -> MechanismErrorKind;
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Error)]
pub struct Gsasl(pub libc::c_uint);
impl Debug for Gsasl {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(rsasl_errname_to_str(self.0 as u32).unwrap_or("UNKNOWN_ERROR"))
    }
}
impl Display for Gsasl {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(rsasl_err_to_str(self.0).unwrap_or("an unknown error was encountered"))
    }
}
impl MechanismError for Gsasl {
    fn kind(&self) -> MechanismErrorKind {
        // TODO: match self and return proper type
        MechanismErrorKind::Protocol
    }
}

#[derive(Debug, Error)]
pub enum StepError {
    #[error("IO error occurred: {source}")]
    Io {
        #[from]
        source: std::io::Error,
    },

    #[cfg(feature = "provider_base64")]
    #[error("base64 wrapping failed: {source}")]
    Base64 {
        #[from]
        source: base64::DecodeError,
    },

    #[error("input data was required but not provided")]
    /// Mechanism was called without input data when requiring some
    InputDataRequired,

    #[error("step was called after mechanism finished")]
    MechanismDone,

    #[error("internal mechanism error: {0}")]
    MechanismError(Box<dyn MechanismError>),

    #[error("callback error: {0}")]
    CallbackError(
        #[from]
        #[source]
        CallbackError,
    ),

    #[error("validation error: {0}")]
    ValidationError(
        #[from]
        #[source]
        ValidationError,
    ),
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("IO error occurred: {source}")]
    Io {
        #[from]
        source: std::io::Error,
    },

    #[cfg(feature = "provider_base64")]
    #[error("base64 wrapping failed: {source}")]
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

    #[error("callback error: {0}")]
    CallbackError(
        #[from]
        #[source]
        CallbackError,
    ),

    #[error("validation error: {0}")]
    ValidationError(
        #[from]
        #[source]
        ValidationError,
    ),

    #[error("callback did not validate the authentication exchange")]
    NoValidate,

    #[error(transparent)]
    Gsasl(Gsasl),
}
static_assertions::assert_impl_all!(SessionError: Send, Sync);

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
}

impl<T: MechanismError + 'static> From<T> for SessionError {
    fn from(e: T) -> Self {
        Self::MechanismError(Box::new(e))
    }
}

#[derive(Debug, Error)]
/// The error type for rsasl errors originating from the `SASL` type
///
pub enum SASLError {
    #[error("mechanism name is invalid: {0}")]
    MechanismNameError(
        #[source]
        #[from]
        MechanismNameError,
    ),

    #[error("provided mechanism name is not supported")]
    UnknownMechanism,

    #[error("no shared mechanism found")]
    NoSharedMechanism,

    #[error(transparent)]
    Gsasl(#[from] Gsasl),
}

impl SASLError {
    pub fn unknown_mechanism(_mechanism: &Mechname) -> Self {
        Self::UnknownMechanism
    }
}

/// Convert an error code to a human readable description of that error
pub fn rsasl_err_to_str(err: libc::c_uint) -> Option<&'static str> {
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
pub fn gsasl_err_to_str(err: libc::c_uint) -> &'static str {
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
pub fn rsasl_errname_to_str(err: libc::c_uint) -> Option<&'static str> {
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
pub fn gsasl_errname_to_str(err: libc::c_uint) -> &'static str {
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
