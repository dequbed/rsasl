use std::any::{Any, TypeId};
use std::ffi::CString;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::marker::PhantomData;
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
    type Item: Any;
    fn code() -> Gsasl_property where Self: Sized;
    fn as_const() -> &'static dyn GetProperty;
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
pub struct OpenID20AuthenticateInBrowser(PhantomData<()>);
impl GetProperty for OpenID20AuthenticateInBrowser {}
pub const OPENID20_AUTHENTICATE_IN_BROWSER: &'static dyn GetProperty = &OpenID20AuthenticateInBrowser(PhantomData);
impl SetProperty for OpenID20AuthenticateInBrowser {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_OPENID20_AUTHENTICATE_IN_BROWSER }
    fn as_const() -> &'static dyn GetProperty {
        OPENID20_AUTHENTICATE_IN_BROWSER
    }
}

#[derive(Debug)]
pub struct Saml20AuthenticateInBrowser(PhantomData<()>);
impl GetProperty for Saml20AuthenticateInBrowser {}
pub const SAML20_AUTHENTICATE_IN_BROWSER: &'static dyn GetProperty = &Saml20AuthenticateInBrowser(PhantomData);
impl SetProperty for Saml20AuthenticateInBrowser {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SAML20_AUTHENTICATE_IN_BROWSER }
    fn as_const() -> &'static dyn GetProperty {
        SAML20_AUTHENTICATE_IN_BROWSER
    }
}

#[derive(Debug)]
pub struct OpenID20OutcomeData(PhantomData<()>);
impl GetProperty for OpenID20OutcomeData {}
pub const OPENID20_OUTCOME_DATA: &'static dyn GetProperty = &OpenID20OutcomeData(PhantomData);
impl SetProperty for OpenID20OutcomeData {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_OPENID20_OUTCOME_DATA }
    fn as_const() -> &'static dyn GetProperty {
        OPENID20_OUTCOME_DATA
    }
}

#[derive(Debug)]
pub struct OpenID20RedirectUrl(PhantomData<()>);

impl GetProperty for OpenID20RedirectUrl {}
pub const OPENID20_REDIRECT_URL: &'static dyn GetProperty = &OpenID20RedirectUrl(PhantomData);

impl SetProperty for OpenID20RedirectUrl {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_OPENID20_REDIRECT_URL }
    fn as_const() -> &'static dyn GetProperty {
        OPENID20_REDIRECT_URL
    }
}

#[derive(Debug)]
pub struct SAML20RedirectUrl(PhantomData<()>);

impl GetProperty for SAML20RedirectUrl {}
pub const SAML20_REDIRECT_URL: &'static dyn GetProperty = &SAML20RedirectUrl(PhantomData);

impl SetProperty for SAML20RedirectUrl {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SAML20_REDIRECT_URL }
    fn as_const() -> &'static dyn GetProperty {
        SAML20_REDIRECT_URL
    }
}

#[derive(Debug)]
pub struct SAML20IDPIdentifier(PhantomData<()>);

impl GetProperty for SAML20IDPIdentifier {}
pub const SAML20_IDP_IDENTIFIER: &'static dyn GetProperty = &SAML20IDPIdentifier(PhantomData);

impl SetProperty for SAML20IDPIdentifier {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SAML20_IDP_IDENTIFIER }
    fn as_const() -> &'static dyn GetProperty {
        SAML20_IDP_IDENTIFIER
    }
}

#[derive(Debug)]
pub struct CBTlsUnique(PhantomData<()>);

impl GetProperty for CBTlsUnique {}
pub const CB_TLS_UNIQUE: &'static dyn GetProperty = &CBTlsUnique(PhantomData);

impl SetProperty for CBTlsUnique {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_CB_TLS_UNIQUE }
    fn as_const() -> &'static dyn GetProperty {
        CB_TLS_UNIQUE
    }
}

#[derive(Debug)]
pub struct ScramStoredkey(PhantomData<()>);

impl GetProperty for ScramStoredkey {}
pub const SCRAM_STOREDKEY: &'static dyn GetProperty = &ScramStoredkey(PhantomData);

impl SetProperty for ScramStoredkey {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SCRAM_STOREDKEY }
    fn as_const() -> &'static dyn GetProperty {
        SCRAM_STOREDKEY
    }
}

#[derive(Debug)]
pub struct ScramServerkey(PhantomData<()>);

impl GetProperty for ScramServerkey {}
pub const SCRAM_SERVERKEY: &'static dyn GetProperty = &ScramServerkey(PhantomData);

impl SetProperty for ScramServerkey {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SCRAM_SERVERKEY }
    fn as_const() -> &'static dyn GetProperty {
        SCRAM_SERVERKEY
    }
}

#[derive(Debug)]
pub struct ScramSaltedPassword(PhantomData<()>);

impl GetProperty for ScramSaltedPassword {}
pub const SCRAM_SALTED_PASSWORD: &'static dyn GetProperty = &ScramSaltedPassword(PhantomData);

impl SetProperty for ScramSaltedPassword {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SCRAM_SALTED_PASSWORD }
    fn as_const() -> &'static dyn GetProperty {
        SCRAM_SALTED_PASSWORD
    }
}

#[derive(Debug)]
pub struct ScramSalt(PhantomData<()>);

impl GetProperty for ScramSalt {}
pub const SCRAM_SALT: &'static dyn GetProperty = &ScramSalt(PhantomData);

impl SetProperty for ScramSalt {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SCRAM_SALT }
    fn as_const() -> &'static dyn GetProperty {
        SCRAM_SALT
    }
}

#[derive(Debug)]
pub struct ScramIter(PhantomData<()>);

impl GetProperty for ScramIter {}
pub const SCRAM_ITER: &'static dyn GetProperty = &ScramIter(PhantomData);

impl SetProperty for ScramIter {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SCRAM_ITER }
    fn as_const() -> &'static dyn GetProperty {
        SCRAM_ITER
    }
}

#[derive(Debug)]
pub struct Qop(PhantomData<()>);

impl GetProperty for Qop {}
pub const QOP: &'static dyn GetProperty = &Qop(PhantomData);

impl SetProperty for Qop {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_QOP }
    fn as_const() -> &'static dyn GetProperty {
        QOP
    }
}

#[derive(Debug)]
pub struct Qops(PhantomData<()>);

impl GetProperty for Qops {}
pub const QOPS: &'static dyn GetProperty = &Qops(PhantomData);

impl SetProperty for Qops {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_QOPS }
    fn as_const() -> &'static dyn GetProperty {
        QOPS
    }
}

#[derive(Debug)]
pub struct DigestMD5HashedPassword(PhantomData<()>);

impl GetProperty for DigestMD5HashedPassword {}
pub const DIGEST_MD5_HASHED_PASSWORD: &'static dyn GetProperty = &DigestMD5HashedPassword(PhantomData);

impl SetProperty for DigestMD5HashedPassword {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_DIGEST_MD5_HASHED_PASSWORD }
    fn as_const() -> &'static dyn GetProperty {
        DIGEST_MD5_HASHED_PASSWORD
    }
}

#[derive(Debug)]
pub struct Realm(PhantomData<()>);

impl GetProperty for Realm {}
pub const REALM: &'static dyn GetProperty = &Realm(PhantomData);

impl SetProperty for Realm {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_REALM }
    fn as_const() -> &'static dyn GetProperty {
        REALM
    }
}

#[derive(Debug)]
pub struct Pin(PhantomData<()>);

impl GetProperty for Pin {}
pub const PIN: &'static dyn GetProperty = &Pin(PhantomData);

impl SetProperty for Pin {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_PIN }
    fn as_const() -> &'static dyn GetProperty {
        PIN
    }
}

#[derive(Debug)]
pub struct SuggestedPin(PhantomData<()>);
pub const SUGGESTED_PIN: &'static dyn GetProperty = &SuggestedPin(PhantomData);

impl GetProperty for SuggestedPin {}

impl SetProperty for SuggestedPin {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SUGGESTED_PIN }
    fn as_const() -> &'static dyn GetProperty {
        SUGGESTED_PIN
    }
}

#[derive(Debug)]
pub struct Passcode(PhantomData<()>);

impl GetProperty for Passcode {}
pub const PASSCODE: &'static dyn GetProperty = &Passcode(PhantomData);

impl SetProperty for Passcode {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_PASSCODE }
    fn as_const() -> &'static dyn GetProperty {
        PASSCODE
    }
}

#[derive(Debug)]
pub struct GssapiDisplayName(PhantomData<()>);

impl GetProperty for GssapiDisplayName {}
pub const GSSAPI_DISPLAY_NAME: &'static dyn GetProperty = &GssapiDisplayName(PhantomData);

impl SetProperty for GssapiDisplayName {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_GSSAPI_DISPLAY_NAME }
    fn as_const() -> &'static dyn GetProperty {
        GSSAPI_DISPLAY_NAME
    }
}

#[derive(Debug)]
pub struct Hostname(PhantomData<()>);

impl GetProperty for Hostname {}
pub const HOSTNAME: &'static dyn GetProperty = &Hostname(PhantomData);

impl SetProperty for Hostname {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_HOSTNAME }
    fn as_const() -> &'static dyn GetProperty {
        HOSTNAME
    }
}

#[derive(Debug)]
pub struct Service(PhantomData<()>);

impl GetProperty for Service {}
pub const SERVICE: &'static dyn GetProperty = &Service(PhantomData);

impl SetProperty for Service {
    type Item = CString;
    fn code() -> Gsasl_property { GSASL_SERVICE }
    fn as_const() -> &'static dyn GetProperty {
        SERVICE
    }
}

#[derive(Debug)]
pub struct AnonymousToken(PhantomData<()>);

impl GetProperty for AnonymousToken {}
pub const ANONYMOUS_TOKEN: &'static dyn GetProperty = &AnonymousToken(PhantomData);

impl SetProperty for AnonymousToken {
    type Item = String;
    fn code() -> Gsasl_property { GSASL_ANONYMOUS_TOKEN }
    fn as_const() -> &'static dyn GetProperty {
        ANONYMOUS_TOKEN
    }
}

#[derive(Debug)]
pub struct Password(PhantomData<()>);

impl GetProperty for Password {}
pub const PASSWORD: &'static dyn GetProperty = &Password(PhantomData);

impl SetProperty for Password {
    type Item = String;
    fn code() -> Gsasl_property { GSASL_PASSWORD }
    fn as_const() -> &'static dyn GetProperty {
        PASSWORD
    }
}

#[derive(Debug)]
pub struct AuthzId(PhantomData<()>);

impl GetProperty for AuthzId {}
pub const AUTHZID: &'static dyn GetProperty = &AuthzId(PhantomData);

impl SetProperty for AuthzId {
    type Item = String;
    fn code() -> Gsasl_property { GSASL_AUTHZID }
    fn as_const() -> &'static dyn GetProperty {
        AUTHZID
    }
}

#[derive(Debug)]
pub struct AuthId(PhantomData<()>);

impl GetProperty for AuthId {}

pub const AUTHID: &'static dyn GetProperty = &AuthId(PhantomData);
impl SetProperty for AuthId {
    type Item = String;
    fn code() -> Gsasl_property { GSASL_AUTHID }
    fn as_const() -> &'static dyn GetProperty {
        AUTHID
    }
}


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