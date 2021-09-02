use gsasl_sys::*;
use std::fmt;
use std::ffi::CStr;

pub type Result<T> = std::result::Result<T, SaslError>;

static UNKNOWN_ERROR: &'static str = "The given error code is unknown to gsasl";

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord)]
/// The gsasl error type
///
/// gsasl has its own error type providing access to human-readable descriptions
pub struct SaslError(pub libc::c_int);

impl SaslError {
    pub fn new(rc: crate::ReturnCode) -> Self {
        Self(rc as libc::c_int)
    }
    pub fn matches(&self, rc: crate::ReturnCode) -> bool {
        self.0 == (rc as libc::c_int)
    }
}

impl fmt::Display for SaslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", gsasl_err_to_str_internal(self.0))
    }
}

/// Convert an error code to a human readable description of that error
pub fn rsasl_err_to_str(err: Gsasl_rc) -> Option<&'static str> {
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
/// i.e. rsasl_errname_to_str(GSASL_OK) -> "GSASL_OK". Returns `None` when an invalid Gsasl_rc is
/// passed.
pub fn rsasl_errname_to_str(err: Gsasl_rc) -> Option<&'static str> {
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
    use super::*;
    use super::Gsasl_rc::*;

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
        assert_eq!(rsasl_errname_to_str(GSASL_KERBEROS_V5_INIT_ERROR), Some("GSASL_KERBEROS_V5_INIT_ERROR"));
        assert_eq!(rsasl_errname_to_str(GSASL_KERBEROS_V5_INTERNAL_ERROR), Some("GSASL_KERBEROS_V5_INTERNAL_ERROR"));
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
        assert_eq!(gsasl_errname_to_str(-1), UNKNOWN_ERROR);
        assert_eq!(
            gsasl_errname_to_str(GSASL_NO_OPENID20_REDIRECT_URL as libc::c_int + 1)
            , UNKNOWN_ERROR
        );
    }

    #[test]
    #[ignore]
    fn err_to_str_valid() {
        assert_eq!(rsasl_err_to_str(GSASL_OK), Some(""));
    }
}
