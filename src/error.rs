use std::fmt;
use std::ffi::CStr;
use std::fmt::{Debug, Display, Formatter};
use base64::DecodeError;
use crate::gsasl::error::{gsasl_strerror, gsasl_strerror_name};
use crate::property::Property;
use crate::PropertyQ;
use crate::validate::Validation;

pub type Result<T> = std::result::Result<T, SASLError>;

static UNKNOWN_ERROR: &'static str = "The given error code is unknown to gsasl";

pub enum SASLError {
    Io {
        source: std::io::Error,
    },
    UnknownMechanism {
        mechanism: [u8; 20],
        len: usize,
    },
    Base64DecodeError {
        source: base64::DecodeError,
    },
    MechanismNameError(MechanismNameError),
    NoSecurityLayer,
    NoCallback {
        property: Property,
    },
    NoValidate {
        validation: Validation,
    },
    NoProperty {
        property: Property,
    },
    AuthenticationFailure {
        reason: &'static str,
    },
    MechanismParseError,
    NoSharedMechanism,
    Gsasl(i32),
}

impl SASLError {
    pub fn no_property<P: PropertyQ>() -> Self {
        Self::NoProperty {
            property: P::property(),
        }
    }
}

impl Debug for SASLError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SASLError::Io { source } => {
                Debug::fmt(source, f)
            },
            SASLError::UnknownMechanism { mechanism, len } => {
                let mechanism = &mechanism[0..*len];
                if let Ok(s) = std::str::from_utf8(mechanism) {
                    write!(f, "UnknownMechanism(\"{}\")", s)
                } else {
                    f.write_str("UnknownMechanism(")?;
                    for b in mechanism.iter() {
                        write!(f, "{:X}", *b)?;
                    }
                    f.write_str(")")
                }
            }
            SASLError::Base64DecodeError { source } => Debug::fmt(source, f),
            SASLError::MechanismNameError(e) => Debug::fmt(e, f),
            SASLError::Gsasl(n) =>
                write!(f, "{}[{}]",
                       rsasl_errname_to_str(*n as u32).unwrap_or("UNKNOWN_ERROR"),
                       n),
            SASLError::NoSecurityLayer => f.write_str("NoSecurityLayer"),
            SASLError::NoValidate { validation } =>
                write!(f, "NoValidate({:?})", validation),
            SASLError::NoCallback { property } => write!(f, "NoCallback({:?})", property),
            SASLError::NoProperty { property } => write!(f, "NoProperty({:?})", property),
            SASLError::AuthenticationFailure { .. } => f.write_str("AuthenticationFailure"),
            SASLError::MechanismParseError => f.write_str("MechanismParseError"),
            SASLError::NoSharedMechanism => f.write_str("NoSharedMechanism"),
        }
    }
}

impl Display for SASLError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SASLError::Io { source } => {
                Display::fmt(source, f)
            },
            SASLError::UnknownMechanism { mechanism, len } => {
                let mechanism = &mechanism[0..*len];
                if let Ok(name) = std::str::from_utf8(mechanism) {
                    write!(f, "mechanism {} is not implemented", name)
                } else {
                    write!(f, "mechanism {:?} is not implemented", mechanism)
                }
            }
            SASLError::Base64DecodeError { source } => {
                Display::fmt(source, f)
            },
            SASLError::MechanismNameError(e) => {
                Display::fmt(e, f)
            },
            SASLError::Gsasl(n) =>
                write!(f, "({}): {}",
                       rsasl_errname_to_str(*n as u32).unwrap_or("UNKNOWN_ERROR"),
                       gsasl_err_to_str_internal(*n)),
            SASLError::NoSecurityLayer => f.write_str("no security layer is installed"),
            SASLError::NoCallback { property } =>
                write!(f,
                       "callback could not provide the requested property {:?}",
                       property),
            SASLError::NoValidate { validation } =>
                write!(f,
                       "no validation callback for {} installed",
                       validation),
            SASLError::NoProperty { property } =>
                write!(f,
                       "required property {} is not set",
                       property),
            SASLError::AuthenticationFailure { reason } =>
                write!(f,
                       "authentication failed: {}",
                       reason),
            SASLError::MechanismParseError =>
                f.write_str("mechanism encountered invalid input data"),
            SASLError::NoSharedMechanism =>
                f.write_str("no shared mechanism found to use"),
        }
    }
}

impl std::error::Error for SASLError {}

impl From<MechanismNameError> for SASLError {
    fn from(e: MechanismNameError) -> Self {
        SASLError::MechanismNameError(e)
    }
}

impl From<base64::DecodeError> for SASLError {
    fn from(source: DecodeError) -> Self {
        SASLError::Base64DecodeError { source }
    }
}

impl From<std::io::Error> for SASLError {
    fn from(source: std::io::Error) -> Self {
        SASLError::Io { source }
    }
}

impl From<i32> for SASLError {
    fn from(e: i32) -> Self {
        SASLError::Gsasl(e)
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub enum MechanismNameError {
    /// Mechanism name longer than 20 characters
    TooLong,

    /// Mechanism name shorter than 1 character
    TooShort,

    /// Mechanism name contained a character outside of [A-Z0-9-_]
    InvalidChars(u8),
}

impl Display for MechanismNameError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            MechanismNameError::TooLong =>
                f.write_str("a mechanism name longer than 20 characters was provided"),
            MechanismNameError::TooShort =>
                f.write_str("mechanism name can't be an empty string"),
            MechanismNameError::InvalidChars(byte)
                if !byte.is_ascii() || byte.is_ascii_whitespace() || byte.is_ascii_control() =>
                    write!(f, "mechanism name contains invalid character {:#x}",
                           byte),
            MechanismNameError::InvalidChars(byte) =>
                write!(f, "mechanism name contains invalid character '{char}'",
                       char = char::from_u32(*byte as u32).unwrap()),
        }
    }
}


/// Convert an error code to a human readable description of that error
pub fn rsasl_err_to_str(err: libc::c_int) -> Option<&'static str> {
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
    Some(cstr.to_str().expect("GSASL library contains bad UTF-8 error descriptions"))
}

/// Convert an error code to a human readable description of that error
#[deprecated(since="1.1.0", note="Use rsasl_err_to_str as replacement")]
pub fn gsasl_err_to_str(err: libc::c_int) -> &'static str {
    gsasl_err_to_str_internal(err)
}

fn gsasl_err_to_str_internal(err: libc::c_int) -> &'static str {
    // gsasl returns the normal zero-terminated string
    let cstr = unsafe { 
        let ptr = gsasl_strerror(err);
        if ptr.is_null() {
            return UNKNOWN_ERROR;
        }

        CStr::from_ptr(ptr)
    };
    // Yes, this could potentially fail. But we're talking about an array of static, compiled-in
    // strings here. If they aren't UTF-8 that's clearly a bug.
    cstr.to_str().expect("GSASL library contains bad UTF-8 error descriptions")
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
    Some(cstr.to_str().expect("GSASL library contains bad UTF-8 error descriptions"))
}


/// Convert an error code to the human readable name of that error.
/// i.e. gsasl_errname_to_str(GSASL_OK) -> "GSASL_OK"
#[deprecated]
pub fn gsasl_errname_to_str(err: libc::c_int) -> &'static str {
    // gsasl returns the normal zero-terminated string
    let cstr = unsafe { 
        let ptr = gsasl_strerror_name(err);
        if ptr.is_null() {
            return UNKNOWN_ERROR;
        }

        CStr::from_ptr(ptr)
    };
    // Yes, this could potentially fail. But we're talking about an array of static, compiled-in
    // strings here. If they aren't UTF-8 that's clearly a bug.
    cstr.to_str().expect("GSASL library contians bad UTF-8 error names")
}

#[cfg(test)]
mod tests {
    use crate::gsasl::consts::*;
    use super::*;

    #[test]
    fn errname_to_str_valid() {
        assert_eq!(rsasl_errname_to_str(GSASL_OK), Some("GSASL_OK"));
        assert_eq!(rsasl_errname_to_str(GSASL_NEEDS_MORE), Some("GSASL_NEEDS_MORE"));
        assert_eq!(rsasl_errname_to_str(GSASL_UNKNOWN_MECHANISM), Some("GSASL_UNKNOWN_MECHANISM"));
        assert_eq!(rsasl_errname_to_str(GSASL_MECHANISM_CALLED_TOO_MANY_TIMES), Some("GSASL_MECHANISM_CALLED_TOO_MANY_TIMES"));
        assert_eq!(rsasl_errname_to_str(GSASL_MALLOC_ERROR), Some("GSASL_MALLOC_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_BASE64_ERROR), Some("GSASL_BASE64_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_CRYPTO_ERROR), Some("GSASL_CRYPTO_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_SASLPREP_ERROR), Some("GSASL_SASLPREP_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_MECHANISM_PARSE_ERROR), Some("GSASL_MECHANISM_PARSE_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_AUTHENTICATION_ERROR), Some("GSASL_AUTHENTICATION_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_INTEGRITY_ERROR), Some("GSASL_INTEGRITY_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_NO_CLIENT_CODE), Some("GSASL_NO_CLIENT_CODE"));
        assert_eq!(rsasl_errname_to_str(GSASL_NO_SERVER_CODE), Some("GSASL_NO_SERVER_CODE"));
        assert_eq!(rsasl_errname_to_str(GSASL_NO_CALLBACK), Some("GSASL_NO_CALLBACK"));
        assert_eq!(rsasl_errname_to_str(GSASL_NO_ANONYMOUS_TOKEN), Some("GSASL_NO_ANONYMOUS_TOKEN"));
        assert_eq!(rsasl_errname_to_str(GSASL_NO_AUTHID), Some("GSASL_NO_AUTHID"));
        assert_eq!(rsasl_errname_to_str(GSASL_NO_AUTHZID), Some("GSASL_NO_AUTHZID"));
        assert_eq!(rsasl_errname_to_str(GSASL_NO_PASSWORD), Some("GSASL_NO_PASSWORD"));
        assert_eq!(rsasl_errname_to_str(GSASL_NO_PASSCODE), Some("GSASL_NO_PASSCODE"));
        assert_eq!(rsasl_errname_to_str(GSASL_NO_PIN), Some("GSASL_NO_PIN"));
        assert_eq!(rsasl_errname_to_str(GSASL_NO_SERVICE), Some("GSASL_NO_SERVICE"));
        assert_eq!(rsasl_errname_to_str(GSASL_NO_HOSTNAME), Some("GSASL_NO_HOSTNAME"));
        assert_eq!(rsasl_errname_to_str(GSASL_NO_CB_TLS_UNIQUE), Some("GSASL_NO_CB_TLS_UNIQUE"));
        assert_eq!(rsasl_errname_to_str(GSASL_NO_SAML20_IDP_IDENTIFIER), Some("GSASL_NO_SAML20_IDP_IDENTIFIER"));
        assert_eq!(rsasl_errname_to_str(GSASL_NO_SAML20_REDIRECT_URL), Some("GSASL_NO_SAML20_REDIRECT_URL"));
        assert_eq!(rsasl_errname_to_str(GSASL_NO_OPENID20_REDIRECT_URL), Some("GSASL_NO_OPENID20_REDIRECT_URL"));
        assert_eq!(rsasl_errname_to_str(GSASL_GSSAPI_RELEASE_BUFFER_ERROR), Some("GSASL_GSSAPI_RELEASE_BUFFER_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_GSSAPI_IMPORT_NAME_ERROR), Some("GSASL_GSSAPI_IMPORT_NAME_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR), Some("GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR), Some("GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_GSSAPI_UNWRAP_ERROR), Some("GSASL_GSSAPI_UNWRAP_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_GSSAPI_WRAP_ERROR), Some("GSASL_GSSAPI_WRAP_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_GSSAPI_ACQUIRE_CRED_ERROR), Some("GSASL_GSSAPI_ACQUIRE_CRED_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_GSSAPI_DISPLAY_NAME_ERROR), Some("GSASL_GSSAPI_DISPLAY_NAME_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR), Some("GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE), Some("GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE"));
        assert_eq!(rsasl_errname_to_str(GSASL_SECURID_SERVER_NEED_NEW_PIN), Some("GSASL_SECURID_SERVER_NEED_NEW_PIN"));
        assert_eq!(rsasl_errname_to_str(GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR), Some("GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR), Some("GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR), Some("GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR), Some("GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_GSSAPI_RELEASE_OID_SET_ERROR), Some("GSASL_GSSAPI_RELEASE_OID_SET_ERROR"));
    }

    #[test]
    fn errname_to_str_invalid() {
        assert_eq!(rsasl_errname_to_str(u32::MAX), None);
        assert_eq!(
            rsasl_errname_to_str(GSASL_NO_OPENID20_REDIRECT_URL as libc::c_uint + 1)
            , None
        );
    }
}
