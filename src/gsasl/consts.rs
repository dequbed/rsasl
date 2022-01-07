use std::any::{Any, TypeId};
use std::ffi::CString;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use crate::as_any::AsAny;
use crate::{Mechname, Session, SessionData};

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
    OPENID20_OUTCOME_DATA(OpenID20OutcomeData),
    OPENID20_REDIRECT_URL(OpenID20RedirectUrl),
    SAML20_REDIRECT_URL(SAML20RedirectUrl),
    SAML20_IDP_IDENTIFIER(SAML20IDPIdentifier),
    CB_TLS_UNIQUE(CBTlsUnique),
    SCRAM_STOREDKEY(ScramStoredkey),
    SCRAM_SERVERKEY(ScramServerkey),
    SCRAM_SALTED_PASSWORD(ScramSaltedPassword),
    SCRAM_SALT(ScramSalt),
    SCRAM_ITER(ScramIter),
    QOP(Qop),
    QOPS(Qops),
    DIGEST_MD5_HASHED_PASSWORD(DigestMD5HashedPassword),
    REALM(Realm),
    PIN(Pin),
    SUGGESTED_PIN(SuggestedPin),
    PASSCODE(Passcode),
    GSSAPI_DISPLAY_NAME(GssapiDisplayName),
    HOSTNAME(Hostname),
    SERVICE(Service),
    ANONYMOUS_TOKEN(AnonymousToken),
    PASSWORD(Password),
    AUTHZID(AuthzId),
    AUTHID(AuthId),
}

impl CallbackAction {
    pub fn code(&self) -> Gsasl_property {
        match self {
            CallbackAction::OPENID20_AUTHENTICATE_IN_BROWSER =>
                GSASL_OPENID20_AUTHENTICATE_IN_BROWSER,
            CallbackAction::SAML20_AUTHENTICATE_IN_BROWSER =>
                GSASL_SAML20_AUTHENTICATE_IN_BROWSER,
            // todo: The rest
            CallbackAction::OPENID20_OUTCOME_DATA(_) => OpenID20OutcomeData::code(),
            CallbackAction::OPENID20_REDIRECT_URL(_) => OpenID20RedirectUrl::code(),
            CallbackAction::SAML20_REDIRECT_URL(_) => SAML20RedirectUrl::code(),
            CallbackAction::SAML20_IDP_IDENTIFIER(_) => SAML20IDPIdentifier::code(),
            CallbackAction::CB_TLS_UNIQUE(_) => CBTlsUnique::code(),
            CallbackAction::SCRAM_STOREDKEY(_) => ScramStoredkey::code(),
            CallbackAction::SCRAM_SERVERKEY(_) => ScramServerkey::code(),
            CallbackAction::SCRAM_SALTED_PASSWORD(_) => ScramSaltedPassword::code(),
            CallbackAction::SCRAM_SALT(_) => ScramSalt::code(),
            CallbackAction::SCRAM_ITER(_) => ScramIter::code(),
            CallbackAction::QOP(_) => Qop::code(),
            CallbackAction::QOPS(_) => Qops::code(),
            CallbackAction::DIGEST_MD5_HASHED_PASSWORD(_) => DigestMD5HashedPassword::code(),
            CallbackAction::REALM(_) => Realm::code(),
            CallbackAction::PIN(_) => Pin::code(),
            CallbackAction::SUGGESTED_PIN(_) => SuggestedPin::code(),
            CallbackAction::PASSCODE(_) => Passcode::code(),
            CallbackAction::GSSAPI_DISPLAY_NAME(_) => GssapiDisplayName::code(),
            CallbackAction::HOSTNAME(_) => Hostname::code(),
            CallbackAction::SERVICE(_) => Service::code(),
            CallbackAction::ANONYMOUS_TOKEN(_) => AnonymousToken::code(),
            CallbackAction::PASSWORD(_) => Password::code(),
            CallbackAction::AUTHZID(_) => AuthzId::code(),
            CallbackAction::AUTHID(_) => AuthId::code(),
        }
    }

    pub fn from_code(code: Gsasl_property) -> Option<Self> {
        match code {
            GSASL_OPENID20_AUTHENTICATE_IN_BROWSER => Some(CallbackAction::OPENID20_AUTHENTICATE_IN_BROWSER),
            GSASL_SAML20_AUTHENTICATE_IN_BROWSER => Some(CallbackAction::SAML20_AUTHENTICATE_IN_BROWSER),
            GSASL_OPENID20_OUTCOME_DATA => Some(CallbackAction::OPENID20_OUTCOME_DATA(OpenID20OutcomeData)),
            GSASL_OPENID20_REDIRECT_URL => Some(CallbackAction::OPENID20_REDIRECT_URL(OpenID20RedirectUrl)),
            GSASL_SAML20_REDIRECT_URL => Some(CallbackAction::SAML20_REDIRECT_URL(SAML20RedirectUrl)),
            GSASL_SAML20_IDP_IDENTIFIER => Some(CallbackAction::SAML20_IDP_IDENTIFIER(SAML20IDPIdentifier)),
            GSASL_CB_TLS_UNIQUE => Some(CallbackAction::CB_TLS_UNIQUE(CBTlsUnique)),
            GSASL_SCRAM_STOREDKEY => Some(CallbackAction::SCRAM_STOREDKEY(ScramStoredkey)),
            GSASL_SCRAM_SERVERKEY => Some(CallbackAction::SCRAM_SERVERKEY(ScramServerkey)),
            GSASL_SCRAM_SALTED_PASSWORD => Some(CallbackAction::SCRAM_SALTED_PASSWORD(ScramSaltedPassword)),
            GSASL_SCRAM_SALT => Some(CallbackAction::SCRAM_SALT(ScramSalt)),
            GSASL_SCRAM_ITER => Some(CallbackAction::SCRAM_ITER(ScramIter)),
            GSASL_QOP => Some(CallbackAction::QOP(Qop)),
            GSASL_QOPS => Some(CallbackAction::QOPS(Qops)),
            GSASL_DIGEST_MD5_HASHED_PASSWORD => Some(CallbackAction::DIGEST_MD5_HASHED_PASSWORD(DigestMD5HashedPassword)),
            GSASL_REALM => Some(CallbackAction::REALM(Realm)),
            GSASL_PIN => Some(CallbackAction::PIN(Pin)),
            GSASL_SUGGESTED_PIN => Some(CallbackAction::SUGGESTED_PIN(SuggestedPin)),
            GSASL_PASSCODE => Some(CallbackAction::PASSCODE(Passcode)),
            GSASL_GSSAPI_DISPLAY_NAME => Some(CallbackAction::GSSAPI_DISPLAY_NAME(GssapiDisplayName)),
            GSASL_HOSTNAME => Some(CallbackAction::HOSTNAME(Hostname)),
            GSASL_SERVICE => Some(CallbackAction::SERVICE(Service)),
            GSASL_ANONYMOUS_TOKEN => Some(CallbackAction::ANONYMOUS_TOKEN(AnonymousToken)),
            GSASL_PASSWORD => Some(CallbackAction::PASSWORD(Password)),
            GSASL_AUTHZID => Some(CallbackAction::AUTHZID(AuthzId)),
            GSASL_AUTHID => Some(CallbackAction::AUTHID(AuthId)),
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

// TODO: 1. Can we make Get-/SetProperty a pure marker trait defining the output type?
// TODO: 2. Check if we can inventory around this for efficient storage.

pub trait GetProperty: 'static + AsAny + Debug {
    fn as_any(&self) -> &dyn Any {
        <Self as AsAny>::as_any_super(self)
    }
}

pub trait SetProperty: GetProperty {
    type Item: Any + Clone;
    fn code() -> Gsasl_property where Self: Sized;
    fn as_const() -> &'static dyn GetProperty {
        todo!()
    }
}

pub trait Property {
    fn code_sta() -> Gsasl_property where Self: Sized;
    fn code_dyn(&self) -> Gsasl_property;
}

impl<T: SetProperty> Property for T {
    fn code_sta() -> Gsasl_property where Self: Sized {
        <T as SetProperty>::code()
    }

    fn code_dyn(&self) -> Gsasl_property {
        <T as SetProperty>::code()
    }
}

impl PartialEq for &'static dyn GetProperty {
    fn eq(&self, other: &Self) -> bool {
        self.type_id() == other.type_id()
    }
}

#[derive(Debug)]
pub struct OpenID20AuthenticateInBrowser;
impl GetProperty for OpenID20AuthenticateInBrowser {}
impl SetProperty for OpenID20AuthenticateInBrowser {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_OPENID20_AUTHENTICATE_IN_BROWSER }
}

#[derive(Debug)]
pub struct Saml20AuthenticateInBrowser;
impl GetProperty for Saml20AuthenticateInBrowser {}
impl SetProperty for Saml20AuthenticateInBrowser {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SAML20_AUTHENTICATE_IN_BROWSER }
}

#[derive(Debug)]
pub struct OpenID20OutcomeData;
impl GetProperty for OpenID20OutcomeData {}
impl SetProperty for OpenID20OutcomeData {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_OPENID20_OUTCOME_DATA }
}

#[derive(Debug)]
pub struct OpenID20RedirectUrl;

impl GetProperty for OpenID20RedirectUrl {}

impl SetProperty for OpenID20RedirectUrl {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_OPENID20_REDIRECT_URL }
}

#[derive(Debug)]
pub struct SAML20RedirectUrl;

impl GetProperty for SAML20RedirectUrl {}

impl SetProperty for SAML20RedirectUrl {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SAML20_REDIRECT_URL }
}

#[derive(Debug)]
pub struct SAML20IDPIdentifier;

impl GetProperty for SAML20IDPIdentifier {}

impl SetProperty for SAML20IDPIdentifier {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SAML20_IDP_IDENTIFIER }
}

#[derive(Debug)]
pub struct CBTlsUnique;

impl GetProperty for CBTlsUnique {}

impl SetProperty for CBTlsUnique {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_CB_TLS_UNIQUE }
}

#[derive(Debug)]
pub struct ScramStoredkey;

impl GetProperty for ScramStoredkey {}

impl SetProperty for ScramStoredkey {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SCRAM_STOREDKEY }
}

#[derive(Debug)]
pub struct ScramServerkey;

impl GetProperty for ScramServerkey {}

impl SetProperty for ScramServerkey {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SCRAM_SERVERKEY }
}

#[derive(Debug)]
pub struct ScramSaltedPassword;

impl GetProperty for ScramSaltedPassword {}

impl SetProperty for ScramSaltedPassword {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SCRAM_SALTED_PASSWORD }
}

#[derive(Debug)]
pub struct ScramSalt;

impl GetProperty for ScramSalt {}

impl SetProperty for ScramSalt {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SCRAM_SALT }
}

#[derive(Debug)]
pub struct ScramIter;

impl GetProperty for ScramIter {}

impl SetProperty for ScramIter {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SCRAM_ITER }
}

#[derive(Debug)]
pub struct Qop;

impl GetProperty for Qop {}

impl SetProperty for Qop {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_QOP }
}

#[derive(Debug)]
pub struct Qops;

impl GetProperty for Qops {}

impl SetProperty for Qops {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_QOPS }
}

#[derive(Debug)]
pub struct DigestMD5HashedPassword;

impl GetProperty for DigestMD5HashedPassword {}

impl SetProperty for DigestMD5HashedPassword {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_DIGEST_MD5_HASHED_PASSWORD }
}

#[derive(Debug)]
pub struct Realm;

impl GetProperty for Realm {}

impl SetProperty for Realm {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_REALM }
}

#[derive(Debug)]
pub struct Pin;

impl GetProperty for Pin {}

impl SetProperty for Pin {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_PIN }
}

#[derive(Debug)]
pub struct SuggestedPin;

impl GetProperty for SuggestedPin {}

impl SetProperty for SuggestedPin {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SUGGESTED_PIN }
}

#[derive(Debug)]
pub struct Passcode;

impl GetProperty for Passcode {}

impl SetProperty for Passcode {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_PASSCODE }
}

#[derive(Debug)]
pub struct GssapiDisplayName;

impl GetProperty for GssapiDisplayName {}

impl SetProperty for GssapiDisplayName {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_GSSAPI_DISPLAY_NAME }
}

#[derive(Debug)]
pub struct Hostname;

impl GetProperty for Hostname {}

impl SetProperty for Hostname {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_HOSTNAME }
}

#[derive(Debug)]
pub struct Service;

impl GetProperty for Service {}

impl SetProperty for Service {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SERVICE }
}

#[derive(Debug)]
pub struct AnonymousToken;

impl GetProperty for AnonymousToken {}

impl SetProperty for AnonymousToken {
    type Item = String;
    fn code() -> Gsasl_property { GSASL_ANONYMOUS_TOKEN }
}

#[derive(Debug)]
pub struct Password;

impl GetProperty for Password {}

impl SetProperty for Password {
    type Item = String;
    fn code() -> Gsasl_property { GSASL_PASSWORD }
}

#[derive(Debug)]
pub struct AuthzId;

impl GetProperty for AuthzId {}

impl SetProperty for AuthzId {
    type Item = String;
    fn code() -> Gsasl_property { GSASL_AUTHZID }
}

#[derive(Debug)]
pub struct AuthId;

impl GetProperty for AuthId {}

pub const AUTHID: &'static dyn GetProperty = &AuthId;
impl SetProperty for AuthId {
    type Item = String;
    fn code() -> Gsasl_property { GSASL_AUTHID }
    fn as_const() -> &'static dyn GetProperty {
        AUTHID
    }
}


pub const OPENID20_AUTHENTICATE_IN_BROWSER: &'static dyn GetProperty = &OpenID20AuthenticateInBrowser;
pub const SAML20_AUTHENTICATE_IN_BROWSER: &'static dyn GetProperty = &Saml20AuthenticateInBrowser;
pub const OPENID20_OUTCOME_DATA: &'static dyn GetProperty = &OpenID20OutcomeData;
pub const OPENID20_REDIRECT_URL: &'static dyn GetProperty = &OpenID20RedirectUrl;
pub const SAML20_REDIRECT_URL: &'static dyn GetProperty = &SAML20RedirectUrl;
pub const SAML20_IDP_IDENTIFIER: &'static dyn GetProperty = &SAML20IDPIdentifier;
pub const CB_TLS_UNIQUE: &'static dyn GetProperty = &CBTlsUnique;
pub const SCRAM_STOREDKEY: &'static dyn GetProperty = &ScramStoredkey;
pub const SCRAM_SERVERKEY: &'static dyn GetProperty = &ScramServerkey;
pub const SCRAM_SALTED_PASSWORD: &'static dyn GetProperty = &ScramSaltedPassword;
pub const SCRAM_SALT: &'static dyn GetProperty = &ScramSalt;
pub const SCRAM_ITER: &'static dyn GetProperty = &ScramIter;
pub const QOP: &'static dyn GetProperty = &Qop;
pub const QOPS: &'static dyn GetProperty = &Qops;
pub const DIGEST_MD5_HASHED_PASSWORD: &'static dyn GetProperty = &DigestMD5HashedPassword;
pub const REALM: &'static dyn GetProperty = &Realm;
pub const PIN: &'static dyn GetProperty = &Pin;
pub const SUGGESTED_PIN: &'static dyn GetProperty = &SuggestedPin;
pub const PASSCODE: &'static dyn GetProperty = &Passcode;
pub const GSSAPI_DISPLAY_NAME: &'static dyn GetProperty = &GssapiDisplayName;
pub const HOSTNAME: &'static dyn GetProperty = &Hostname;
pub const SERVICE: &'static dyn GetProperty = &Service;
pub const ANONYMOUS_TOKEN: &'static dyn GetProperty = &AnonymousToken;
pub const PASSWORD: &'static dyn GetProperty = &Password;
pub const AUTHZID: &'static dyn GetProperty = &AuthzId;

#[cfg(test)]
mod tests {
    use std::any::type_name;
    use std::collections::HashMap;
    use super::*;

    #[test]
    fn test_dyn_prop() {
        fn does(prop: &'static dyn GetProperty) {
            if prop == PASSWORD {
                println!("is OIDC_OUTCOME");
            } else {
                println!("is instead {:?}", prop);
            }
        }

        does(PASSWORD);
    }
}