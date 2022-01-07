use std::any::Any;
use std::ffi::CString;
use crate::Mechname;

pub type RsaslError = libc::c_uint;
pub const GSASL_IO_ERROR: libc::c_uint = 65;
pub const GSASL_GSSAPI_RELEASE_OID_SET_ERROR: libc::c_uint = 64;
pub const GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR: libc::c_uint = 63;
pub const GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR: libc::c_uint = 62;
pub const GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR: libc::c_uint = 61;
pub const GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR: libc::c_uint = 60;
pub const GSASL_SECURID_SERVER_NEED_NEW_PIN: libc::c_uint = 49;
pub const GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE: libc::c_uint = 48;
pub const GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR: libc::c_uint = 45;
pub const GSASL_GSSAPI_DISPLAY_NAME_ERROR: libc::c_uint = 44;
pub const GSASL_GSSAPI_ACQUIRE_CRED_ERROR: libc::c_uint = 43;
pub const GSASL_GSSAPI_WRAP_ERROR: libc::c_uint = 42;
pub const GSASL_GSSAPI_UNWRAP_ERROR: libc::c_uint = 41;
pub const GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR: libc::c_uint = 40;
pub const GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR: libc::c_uint = 39;
pub const GSASL_GSSAPI_IMPORT_NAME_ERROR: libc::c_uint = 38;
pub const GSASL_GSSAPI_RELEASE_BUFFER_ERROR: libc::c_uint = 37;
pub const GSASL_NO_OPENID20_REDIRECT_URL: libc::c_uint = 68;
pub const GSASL_NO_SAML20_REDIRECT_URL: libc::c_uint = 67;
pub const GSASL_NO_SAML20_IDP_IDENTIFIER: libc::c_uint = 66;
pub const GSASL_NO_CB_TLS_UNIQUE: libc::c_uint = 65;
pub const GSASL_NO_HOSTNAME: libc::c_uint = 59;
pub const GSASL_NO_SERVICE: libc::c_uint = 58;
pub const GSASL_NO_PIN: libc::c_uint = 57;
pub const GSASL_NO_PASSCODE: libc::c_uint = 56;
pub const GSASL_NO_PASSWORD: libc::c_uint = 55;
pub const GSASL_NO_AUTHZID: libc::c_uint = 54;
pub const GSASL_NO_AUTHID: libc::c_uint = 53;
pub const GSASL_NO_ANONYMOUS_TOKEN: libc::c_uint = 52;
pub const GSASL_NO_CALLBACK: libc::c_uint = 51;
pub const GSASL_NO_SERVER_CODE: libc::c_uint = 36;
pub const GSASL_NO_CLIENT_CODE: libc::c_uint = 35;
pub const GSASL_INTEGRITY_ERROR: libc::c_uint = 33;
pub const GSASL_AUTHENTICATION_ERROR: libc::c_uint = 31;
pub const GSASL_MECHANISM_PARSE_ERROR: libc::c_uint = 30;
pub const GSASL_SASLPREP_ERROR: libc::c_uint = 29;
pub const GSASL_CRYPTO_ERROR: libc::c_uint = 9;
pub const GSASL_BASE64_ERROR: libc::c_uint = 8;
pub const GSASL_MALLOC_ERROR: libc::c_uint = 7;
pub const GSASL_MECHANISM_CALLED_TOO_MANY_TIMES: libc::c_uint = 3;
pub const GSASL_UNKNOWN_MECHANISM: libc::c_uint = 2;
pub const GSASL_NEEDS_MORE: libc::c_uint = 1;
pub const GSASL_OK: libc::c_uint = 0;

pub enum CallbackAction {
    OPENID20_AUTHENTICATE_IN_BROWSER,
    SAML20_AUTHENTICATE_IN_BROWSER,
    OPENID20_OUTCOME_DATA(OPENID20_OUTCOME_DATA),
    OPENID20_REDIRECT_URL(OPENID20_REDIRECT_URL),
    SAML20_REDIRECT_URL(SAML20_REDIRECT_URL),
    SAML20_IDP_IDENTIFIER(SAML20_IDP_IDENTIFIER),
    CB_TLS_UNIQUE(CB_TLS_UNIQUE),
    SCRAM_STOREDKEY(SCRAM_STOREDKEY),
    SCRAM_SERVERKEY(SCRAM_SERVERKEY),
    SCRAM_SALTED_PASSWORD(SCRAM_SALTED_PASSWORD),
    SCRAM_SALT(SCRAM_SALT),
    SCRAM_ITER(SCRAM_ITER),
    QOP(QOP),
    QOPS(QOPS),
    DIGEST_MD5_HASHED_PASSWORD(DIGEST_MD5_HASHED_PASSWORD),
    REALM(REALM),
    PIN(PIN),
    SUGGESTED_PIN(SUGGESTED_PIN),
    PASSCODE(PASSCODE),
    GSSAPI_DISPLAY_NAME(GSSAPI_DISPLAY_NAME),
    HOSTNAME(HOSTNAME),
    SERVICE(SERVICE),
    ANONYMOUS_TOKEN(ANONYMOUS_TOKEN),
    PASSWORD(PASSWORD),
    AUTHZID(AUTHZID),
    AUTHID(AUTHID),
}

impl CallbackAction {
    pub fn code(&self) -> Gsasl_property {
        match self {
            CallbackAction::OPENID20_AUTHENTICATE_IN_BROWSER =>
                GSASL_OPENID20_AUTHENTICATE_IN_BROWSER,
            CallbackAction::SAML20_AUTHENTICATE_IN_BROWSER =>
                GSASL_SAML20_AUTHENTICATE_IN_BROWSER,
            // todo: The rest
            CallbackAction::OPENID20_OUTCOME_DATA(_) => OPENID20_OUTCOME_DATA::code(),
            CallbackAction::OPENID20_REDIRECT_URL(_) => OPENID20_REDIRECT_URL::code(),
            CallbackAction::SAML20_REDIRECT_URL(_) => SAML20_REDIRECT_URL::code(),
            CallbackAction::SAML20_IDP_IDENTIFIER(_) => SAML20_IDP_IDENTIFIER::code(),
            CallbackAction::CB_TLS_UNIQUE(_) => CB_TLS_UNIQUE::code(),
            CallbackAction::SCRAM_STOREDKEY(_) => SCRAM_STOREDKEY::code(),
            CallbackAction::SCRAM_SERVERKEY(_) => SCRAM_SERVERKEY::code(),
            CallbackAction::SCRAM_SALTED_PASSWORD(_) => SCRAM_SALTED_PASSWORD::code(),
            CallbackAction::SCRAM_SALT(_) => SCRAM_SALT::code(),
            CallbackAction::SCRAM_ITER(_) => SCRAM_ITER::code(),
            CallbackAction::QOP(_) => QOP::code(),
            CallbackAction::QOPS(_) => QOPS::code(),
            CallbackAction::DIGEST_MD5_HASHED_PASSWORD(_) => DIGEST_MD5_HASHED_PASSWORD::code(),
            CallbackAction::REALM(_) => REALM::code(),
            CallbackAction::PIN(_) => PIN::code(),
            CallbackAction::SUGGESTED_PIN(_) => SUGGESTED_PIN::code(),
            CallbackAction::PASSCODE(_) => PASSCODE::code(),
            CallbackAction::GSSAPI_DISPLAY_NAME(_) => GSSAPI_DISPLAY_NAME::code(),
            CallbackAction::HOSTNAME(_) => HOSTNAME::code(),
            CallbackAction::SERVICE(_) => SERVICE::code(),
            CallbackAction::ANONYMOUS_TOKEN(_) => ANONYMOUS_TOKEN::code(),
            CallbackAction::PASSWORD(_) => PASSWORD::code(),
            CallbackAction::AUTHZID(_) => AUTHZID::code(),
            CallbackAction::AUTHID(_) => AUTHID::code(),
        }
    }

    pub fn from_code(code: Gsasl_property) -> Option<Self> {
        match code {
            GSASL_OPENID20_AUTHENTICATE_IN_BROWSER => Some(CallbackAction::OPENID20_AUTHENTICATE_IN_BROWSER),
            GSASL_SAML20_AUTHENTICATE_IN_BROWSER => Some(CallbackAction::SAML20_AUTHENTICATE_IN_BROWSER),
            GSASL_OPENID20_OUTCOME_DATA => Some(CallbackAction::OPENID20_OUTCOME_DATA(OPENID20_OUTCOME_DATA)),
            GSASL_OPENID20_REDIRECT_URL => Some(CallbackAction::OPENID20_REDIRECT_URL(OPENID20_REDIRECT_URL)),
            GSASL_SAML20_REDIRECT_URL => Some(CallbackAction::SAML20_REDIRECT_URL(SAML20_REDIRECT_URL)),
            GSASL_SAML20_IDP_IDENTIFIER => Some(CallbackAction::SAML20_IDP_IDENTIFIER(SAML20_IDP_IDENTIFIER)),
            GSASL_CB_TLS_UNIQUE => Some(CallbackAction::CB_TLS_UNIQUE(CB_TLS_UNIQUE)),
            GSASL_SCRAM_STOREDKEY => Some(CallbackAction::SCRAM_STOREDKEY(SCRAM_STOREDKEY)),
            GSASL_SCRAM_SERVERKEY => Some(CallbackAction::SCRAM_SERVERKEY(SCRAM_SERVERKEY)),
            GSASL_SCRAM_SALTED_PASSWORD => Some(CallbackAction::SCRAM_SALTED_PASSWORD(SCRAM_SALTED_PASSWORD)),
            GSASL_SCRAM_SALT => Some(CallbackAction::SCRAM_SALT(SCRAM_SALT)),
            GSASL_SCRAM_ITER => Some(CallbackAction::SCRAM_ITER(SCRAM_ITER)),
            GSASL_QOP => Some(CallbackAction::QOP(QOP)),
            GSASL_QOPS => Some(CallbackAction::QOPS(QOPS)),
            GSASL_DIGEST_MD5_HASHED_PASSWORD => Some(CallbackAction::DIGEST_MD5_HASHED_PASSWORD(DIGEST_MD5_HASHED_PASSWORD)),
            GSASL_REALM => Some(CallbackAction::REALM(REALM)),
            GSASL_PIN => Some(CallbackAction::PIN(PIN)),
            GSASL_SUGGESTED_PIN => Some(CallbackAction::SUGGESTED_PIN(SUGGESTED_PIN)),
            GSASL_PASSCODE => Some(CallbackAction::PASSCODE(PASSCODE)),
            GSASL_GSSAPI_DISPLAY_NAME => Some(CallbackAction::GSSAPI_DISPLAY_NAME(GSSAPI_DISPLAY_NAME)),
            GSASL_HOSTNAME => Some(CallbackAction::HOSTNAME(HOSTNAME)),
            GSASL_SERVICE => Some(CallbackAction::SERVICE(SERVICE)),
            GSASL_ANONYMOUS_TOKEN => Some(CallbackAction::ANONYMOUS_TOKEN(ANONYMOUS_TOKEN)),
            GSASL_PASSWORD => Some(CallbackAction::PASSWORD(PASSWORD)),
            GSASL_AUTHZID => Some(CallbackAction::AUTHZID(AUTHZID)),
            GSASL_AUTHID => Some(CallbackAction::AUTHID(AUTHID)),
            _ => None,
        }

    }
}

pub type Gsasl_property = libc::c_uint;
pub const GSASL_VALIDATE_OPENID20: Gsasl_property = 506;
pub const GSASL_VALIDATE_SAML20: Gsasl_property = 505;
pub const GSASL_VALIDATE_SECURID: Gsasl_property = 504;
pub const GSASL_VALIDATE_GSSAPI: Gsasl_property = 503;
pub const GSASL_VALIDATE_ANONYMOUS: Gsasl_property = 502;
pub const GSASL_VALIDATE_EXTERNAL: Gsasl_property = 501;
pub const GSASL_VALIDATE_SIMPLE: Gsasl_property = 500;

pub const GSASL_OPENID20_AUTHENTICATE_IN_BROWSER: Gsasl_property = 251;
pub const GSASL_SAML20_AUTHENTICATE_IN_BROWSER: Gsasl_property = 250;
pub const GSASL_OPENID20_OUTCOME_DATA: Gsasl_property = 22;
pub const GSASL_OPENID20_REDIRECT_URL: Gsasl_property = 21;
pub const GSASL_SAML20_REDIRECT_URL: Gsasl_property = 20;
pub const GSASL_SAML20_IDP_IDENTIFIER: Gsasl_property = 19;
pub const GSASL_CB_TLS_UNIQUE: Gsasl_property = 18;
pub const GSASL_SCRAM_STOREDKEY: Gsasl_property = 24;
pub const GSASL_SCRAM_SERVERKEY: Gsasl_property = 23;
pub const GSASL_SCRAM_SALTED_PASSWORD: Gsasl_property = 17;
pub const GSASL_SCRAM_SALT: Gsasl_property = 16;
pub const GSASL_SCRAM_ITER: Gsasl_property = 15;
pub const GSASL_QOP: Gsasl_property = 14;
pub const GSASL_QOPS: Gsasl_property = 13;
pub const GSASL_DIGEST_MD5_HASHED_PASSWORD: Gsasl_property = 12;
pub const GSASL_REALM: Gsasl_property = 11;
pub const GSASL_PIN: Gsasl_property = 10;
pub const GSASL_SUGGESTED_PIN: Gsasl_property = 9;
pub const GSASL_PASSCODE: Gsasl_property = 8;
pub const GSASL_GSSAPI_DISPLAY_NAME: Gsasl_property = 7;
pub const GSASL_HOSTNAME: Gsasl_property = 6;
pub const GSASL_SERVICE: Gsasl_property = 5;
pub const GSASL_ANONYMOUS_TOKEN: Gsasl_property = 4;
pub const GSASL_PASSWORD: Gsasl_property = 3;
pub const GSASL_AUTHZID: Gsasl_property = 2;
pub const GSASL_AUTHID: Gsasl_property = 1;

// TODO: 1. Make this a pure marker trait defining the output type.
// TODO: 2. Check if we can inventory around this for efficient storage.
pub trait Property {
    type Item: Any + Clone;
    fn code() -> Gsasl_property where Self: Sized;
}

pub struct OPENID20_OUTCOME_DATA;
impl Property for OPENID20_OUTCOME_DATA {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_OPENID20_OUTCOME_DATA }
}
pub struct OPENID20_REDIRECT_URL;
impl Property for OPENID20_REDIRECT_URL {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_OPENID20_REDIRECT_URL }
}
pub struct SAML20_REDIRECT_URL;
impl Property for SAML20_REDIRECT_URL {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SAML20_REDIRECT_URL }
}
pub struct SAML20_IDP_IDENTIFIER;
impl Property for SAML20_IDP_IDENTIFIER {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SAML20_IDP_IDENTIFIER }
}
pub struct CB_TLS_UNIQUE;
impl Property for CB_TLS_UNIQUE {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_CB_TLS_UNIQUE }
}
pub struct SCRAM_STOREDKEY;
impl Property for SCRAM_STOREDKEY {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SCRAM_STOREDKEY }
}
pub struct SCRAM_SERVERKEY;
impl Property for SCRAM_SERVERKEY {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SCRAM_SERVERKEY }
}
pub struct SCRAM_SALTED_PASSWORD;
impl Property for SCRAM_SALTED_PASSWORD {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SCRAM_SALTED_PASSWORD }
}
pub struct SCRAM_SALT;
impl Property for SCRAM_SALT {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SCRAM_SALT }
}
pub struct SCRAM_ITER;
impl Property for SCRAM_ITER {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SCRAM_ITER }
}
pub struct QOP;
impl Property for QOP {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_QOP }
}
pub struct QOPS;
impl Property for QOPS {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_QOPS }
}
pub struct DIGEST_MD5_HASHED_PASSWORD;
impl Property for DIGEST_MD5_HASHED_PASSWORD {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_DIGEST_MD5_HASHED_PASSWORD }
}
pub struct REALM;
impl Property for REALM {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_REALM }
}
pub struct PIN;
impl Property for PIN {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_PIN }
}
pub struct SUGGESTED_PIN;
impl Property for SUGGESTED_PIN {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SUGGESTED_PIN }
}
pub struct PASSCODE;
impl Property for PASSCODE {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_PASSCODE }
}
pub struct GSSAPI_DISPLAY_NAME;
impl Property for GSSAPI_DISPLAY_NAME {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_GSSAPI_DISPLAY_NAME }
}
pub struct HOSTNAME;
impl Property for HOSTNAME {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_HOSTNAME }
}
pub struct SERVICE;
impl Property for SERVICE {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SERVICE }
}
pub struct ANONYMOUS_TOKEN;
impl Property for ANONYMOUS_TOKEN {
    type Item = String;
    fn code() -> Gsasl_property { GSASL_ANONYMOUS_TOKEN }
}
pub struct PASSWORD;
impl Property for PASSWORD {
    type Item = String;
    fn code() -> Gsasl_property { GSASL_PASSWORD }
}
pub struct AUTHZID;
impl Property for AUTHZID {
    type Item = String;
    fn code() -> Gsasl_property { GSASL_AUTHZID }
}
pub struct AUTHID;
impl Property for AUTHID {
    type Item = String;
    fn code() -> Gsasl_property { GSASL_AUTHID }
}
