use ::libc;
use crate::gsasl::consts::Gsasl_property;
use crate::gsasl::consts::*;
use crate::property::*;
use crate::session::SessionData;
use crate::Shared;
use crate::validate::*;

pub(crate) unsafe fn gsasl_callback(_ctx: *mut Shared,
                             sctx: &mut SessionData,
                             prop: Gsasl_property)
 -> libc::c_int {

    if let Some(cb) = sctx.callback.clone() {
        let res = match prop {
            GSASL_VALIDATE_SIMPLE => sctx.validate(SIMPLE),
            GSASL_VALIDATE_OPENID20 => sctx.validate(OPENID20),
            GSASL_VALIDATE_SAML20 => sctx.validate(SAML20),
            GSASL_VALIDATE_SECURID => sctx.validate(SECURID),
            GSASL_VALIDATE_GSSAPI => sctx.validate(GSSAPI),
            GSASL_VALIDATE_ANONYMOUS => sctx.validate(ANONYMOUS),
            GSASL_VALIDATE_EXTERNAL => sctx.validate(EXTERNAL),

            GSASL_OPENID20_AUTHENTICATE_IN_BROWSER => cb.provide_prop(sctx, OPENID20_AUTHENTICATE_IN_BROWSER),
            GSASL_SAML20_AUTHENTICATE_IN_BROWSER => cb.provide_prop(sctx, SAML20_AUTHENTICATE_IN_BROWSER),
            GSASL_OPENID20_OUTCOME_DATA => cb.provide_prop(sctx, OPENID20_OUTCOME_DATA),
            GSASL_OPENID20_REDIRECT_URL => cb.provide_prop(sctx, OPENID20_REDIRECT_URL),
            GSASL_SAML20_REDIRECT_URL => cb.provide_prop(sctx, SAML20_REDIRECT_URL),
            GSASL_SAML20_IDP_IDENTIFIER => cb.provide_prop(sctx, SAML20_IDP_IDENTIFIER),
            GSASL_CB_TLS_UNIQUE => cb.provide_prop(sctx, CB_TLS_UNIQUE),
            GSASL_SCRAM_STOREDKEY => cb.provide_prop(sctx, SCRAM_STOREDKEY),
            GSASL_SCRAM_SERVERKEY => cb.provide_prop(sctx, SCRAM_SERVERKEY),
            GSASL_SCRAM_SALTED_PASSWORD => cb.provide_prop(sctx, SCRAM_SALTED_PASSWORD),
            GSASL_SCRAM_SALT => cb.provide_prop(sctx, SCRAM_SALT),
            GSASL_SCRAM_ITER => cb.provide_prop(sctx, SCRAM_ITER),
            GSASL_QOP => cb.provide_prop(sctx, QOP),
            GSASL_QOPS => cb.provide_prop(sctx, QOPS),
            GSASL_DIGEST_MD5_HASHED_PASSWORD => cb.provide_prop(sctx, DIGEST_MD5_HASHED_PASSWORD),
            GSASL_REALM => cb.provide_prop(sctx, REALM),
            GSASL_PIN => cb.provide_prop(sctx, PIN),
            GSASL_SUGGESTED_PIN => cb.provide_prop(sctx, SUGGESTED_PIN),
            GSASL_PASSCODE => cb.provide_prop(sctx, PASSCODE),
            GSASL_GSSAPI_DISPLAY_NAME => cb.provide_prop(sctx, GSSAPI_DISPLAY_NAME),
            GSASL_HOSTNAME => cb.provide_prop(sctx, HOSTNAME),
            GSASL_SERVICE => cb.provide_prop(sctx, SERVICE),
            GSASL_ANONYMOUS_TOKEN => cb.provide_prop(sctx, ANONYMOUS_TOKEN),
            GSASL_PASSWORD => cb.provide_prop(sctx, PASSWORD),
            GSASL_AUTHZID => cb.provide_prop(sctx, AUTHZID),
            GSASL_AUTHID => cb.provide_prop(sctx, AUTHID),
            _ => unreachable!(),
        };

        if res.is_err() {
            GSASL_NO_CALLBACK as i32
        } else {
            GSASL_OK as i32
        }
    } else {
        GSASL_NO_CALLBACK as i32
    }
}
