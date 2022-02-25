use crate::property::properties::*;
use crate::Property;

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

pub fn property_from_code(code: Gsasl_property) -> Option<Property> {
    match code {
        GSASL_OPENID20_AUTHENTICATE_IN_BROWSER => Some(OPENID20_AUTHENTICATE_IN_BROWSER),
        GSASL_SAML20_AUTHENTICATE_IN_BROWSER => Some(SAML20_AUTHENTICATE_IN_BROWSER),
        GSASL_OPENID20_OUTCOME_DATA => Some(OPENID20_OUTCOME_DATA),
        GSASL_OPENID20_REDIRECT_URL => Some(OPENID20_REDIRECT_URL),
        GSASL_SAML20_REDIRECT_URL => Some(SAML20_REDIRECT_URL),
        GSASL_SAML20_IDP_IDENTIFIER => Some(SAML20_IDP_IDENTIFIER),
        GSASL_CB_TLS_UNIQUE => Some(CB_TLS_UNIQUE),
        GSASL_SCRAM_STOREDKEY => Some(SCRAM_STOREDKEY),
        GSASL_SCRAM_SERVERKEY => Some(SCRAM_SERVERKEY),
        GSASL_SCRAM_SALTED_PASSWORD => Some(SCRAM_SALTED_PASSWORD),
        GSASL_SCRAM_SALT => Some(SCRAM_SALT),
        GSASL_SCRAM_ITER => Some(SCRAM_ITER),
        GSASL_QOP => Some(QOP),
        GSASL_QOPS => Some(QOPS),
        GSASL_DIGEST_MD5_HASHED_PASSWORD => Some(DIGEST_MD5_HASHED_PASSWORD),
        GSASL_REALM => Some(REALM),
        GSASL_PIN => Some(PIN),
        GSASL_SUGGESTED_PIN => Some(SUGGESTED_PIN),
        GSASL_PASSCODE => Some(PASSCODE),
        GSASL_GSSAPI_DISPLAY_NAME => Some(GSSAPI_DISPLAY_NAME),
        GSASL_HOSTNAME => Some(HOSTNAME),
        GSASL_SERVICE => Some(SERVICE),
        GSASL_ANONYMOUS_TOKEN => Some(ANONYMOUS_TOKEN),
        GSASL_PASSWORD => Some(PASSWORD),
        GSASL_AUTHZID => Some(AUTHZID),
        GSASL_AUTHID => Some(AUTHID),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::property::*;

    #[test]
    fn test_property_from_code() {
        let data: &[(Gsasl_property, Property)] = &[
            (GSASL_OPENID20_OUTCOME_DATA, OpenID20OutcomeData::property()),
            (GSASL_OPENID20_REDIRECT_URL, OpenID20RedirectUrl::property()),
            (GSASL_SAML20_REDIRECT_URL, SAML20RedirectUrl::property()),
            (GSASL_SAML20_IDP_IDENTIFIER, SAML20IDPIdentifier::property()),
            (GSASL_CB_TLS_UNIQUE, CBTlsUnique::property()),
            (GSASL_SCRAM_STOREDKEY, ScramStoredkey::property()),
            (GSASL_SCRAM_SERVERKEY, ScramServerkey::property()),
            (GSASL_SCRAM_SALTED_PASSWORD, ScramSaltedPassword::property()),
            (GSASL_SCRAM_SALT, ScramSalt::property()),
            (GSASL_SCRAM_ITER, ScramIter::property()),
            (GSASL_QOP, Qop::property()),
            (GSASL_QOPS, Qops::property()),
            (
                GSASL_DIGEST_MD5_HASHED_PASSWORD,
                DigestMD5HashedPassword::property(),
            ),
            (GSASL_REALM, Realm::property()),
            (GSASL_PIN, Pin::property()),
            (GSASL_SUGGESTED_PIN, SuggestedPin::property()),
            (GSASL_PASSCODE, Passcode::property()),
            (GSASL_GSSAPI_DISPLAY_NAME, GssapiDisplayName::property()),
            (GSASL_HOSTNAME, Hostname::property()),
            (GSASL_SERVICE, Service::property()),
            (GSASL_ANONYMOUS_TOKEN, AnonymousToken::property()),
            (GSASL_PASSWORD, Password::property()),
            (GSASL_AUTHZID, AuthzId::property()),
            (GSASL_AUTHID, AuthId::property()),
        ];
        for (idx, (code, should)) in data.iter().enumerate() {
            println!("Checking ({}) {:?}: \"{}\"", code, should, should);
            let prop = property_from_code(*code).expect("Failed to convert");
            println!("{:?} == {:?}", prop, should);
            assert_eq!(&prop, should);
            let before = &data[0..idx];
            let after = &data[(idx + 1)..];
            for (_code, should) in before.iter().chain(after.iter()) {
                println!("{} != {}", prop.name(), should.name());
                assert_ne!(&prop, should);
            }
            println!("\n");
        }
    }
}
