use crate::gsasl::consts::Gsasl_property;

use crate::session::MechanismData;

use crate::Shared;
use ::libc;

pub(crate) unsafe fn gsasl_callback(
    _ctx: *mut Shared,
    _sctx: &mut MechanismData,
    _prop: Gsasl_property,
) -> libc::c_int {
    /*
    let res = match prop {
        GSASL_VALIDATE_SIMPLE => sctx.validate(&SIMPLE),
        GSASL_VALIDATE_OPENID20 => sctx.validate(&OPENID20),
        GSASL_VALIDATE_SAML20 => sctx.validate(&SAML20),
        GSASL_VALIDATE_SECURID => sctx.validate(&SECURID),
        GSASL_VALIDATE_GSSAPI => sctx.validate(&GSSAPI),
        GSASL_VALIDATE_ANONYMOUS => sctx.validate(&ANONYMOUS),
        GSASL_VALIDATE_EXTERNAL => sctx.validate(&EXTERNAL),

        GSASL_OPENID20_AUTHENTICATE_IN_BROWSER => {
            sctx.callback_property(OPENID20_AUTHENTICATE_IN_BROWSER)
        }
        GSASL_SAML20_AUTHENTICATE_IN_BROWSER => {
            sctx.callback_property(SAML20_AUTHENTICATE_IN_BROWSER)
        }
        GSASL_OPENID20_OUTCOME_DATA => sctx.callback_property(OPENID20_OUTCOME_DATA),
        GSASL_OPENID20_REDIRECT_URL => sctx.callback_property(OPENID20_REDIRECT_URL),
        GSASL_SAML20_REDIRECT_URL => sctx.callback_property(SAML20_REDIRECT_URL),
        GSASL_SAML20_IDP_IDENTIFIER => sctx.callback_property(SAML20_IDP_IDENTIFIER),
        GSASL_CB_TLS_UNIQUE => sctx.callback_property(CB_TLS_UNIQUE),
        GSASL_SCRAM_STOREDKEY => sctx.callback_property(SCRAM_STOREDKEY),
        GSASL_SCRAM_SERVERKEY => sctx.callback_property(SCRAM_SERVERKEY),
        GSASL_SCRAM_SALTED_PASSWORD => sctx.callback_property(SCRAM_SALTED_PASSWORD),
        GSASL_SCRAM_SALT => sctx.callback_property(SCRAM_SALT),
        GSASL_SCRAM_ITER => sctx.callback_property(SCRAM_ITER),
        GSASL_QOP => sctx.callback_property(QOP),
        GSASL_QOPS => sctx.callback_property(QOPS),
        GSASL_DIGEST_MD5_HASHED_PASSWORD => sctx.callback_property(DIGEST_MD5_HASHED_PASSWORD),
        GSASL_REALM => sctx.callback_property(REALM),
        GSASL_PIN => sctx.callback_property(PIN),
        GSASL_SUGGESTED_PIN => sctx.callback_property(SUGGESTED_PIN),
        GSASL_PASSCODE => sctx.callback_property(PASSCODE),
        GSASL_GSSAPI_DISPLAY_NAME => sctx.callback_property(GSSAPI_DISPLAY_NAME),
        GSASL_HOSTNAME => sctx.callback_property(HOSTNAME),
        GSASL_SERVICE => sctx.callback_property(SERVICE),
        GSASL_ANONYMOUS_TOKEN => sctx.callback_property(ANONYMOUS_TOKEN),
        GSASL_PASSWORD => sctx.callback_property(PASSWORD),
        GSASL_AUTHZID => sctx.callback_property(AUTHZID),
        GSASL_AUTHID => sctx.callback_property(AUTHID),
        _ => unreachable!(),
    };

    if res.is_err() {
        GSASL_NO_CALLBACK as i32
    } else {
        GSASL_OK as i32
    }
     */
    unimplemented!()
}
