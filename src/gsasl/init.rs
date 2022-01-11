use ::libc;
use crate::gsasl::consts::GSASL_OK;
use crate::gsasl::register::gsasl_register;
use crate::registry::Registry;

extern "C" {
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
}

#[no_mangle]
pub static mut GSASL_VALID_MECHANISM_CHARACTERS: *const libc::c_char =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_\x00" as *const u8 as
        *const libc::c_char;

pub(crate) unsafe fn register_builtin_mechs(ctx: &mut Registry) -> libc::c_int {
    #[cfg(feature = "anonymous")]
        {
            use crate::mechanisms::anonymous::mechinfo::gsasl_anonymous_mechanism;
            let rc = gsasl_register(ctx, &mut gsasl_anonymous_mechanism);
            if rc != GSASL_OK as libc::c_int { return rc }
        }

    #[cfg(feature = "external")]
        {
            use crate::mechanisms::external::mechinfo::gsasl_external_mechanism;
            let rc = gsasl_register(ctx, &mut gsasl_external_mechanism);
            if rc != GSASL_OK as libc::c_int { return rc }
        }

    #[cfg(feature = "login")]
        {
            use crate::mechanisms::login::mechinfo::gsasl_login_mechanism;
            let rc = gsasl_register(ctx, &mut gsasl_login_mechanism);
            if rc != GSASL_OK as libc::c_int { return rc }
        }

    #[cfg(feature = "securid")]
        {
            use crate::mechanisms::securid::mechinfo::gsasl_securid_mechanism;
            let rc = gsasl_register(ctx, &mut gsasl_securid_mechanism);
            if rc != GSASL_OK as libc::c_int { return rc }
        }
    /* USE_NTLM */


    #[cfg(feature = "digest-md5")]
        {
            use crate::mechanisms::digest_md5::mechinfo::gsasl_digest_md5_mechanism;
            let rc = gsasl_register(ctx, &mut gsasl_digest_md5_mechanism);
            if rc != GSASL_OK as libc::c_int { return rc }
        }

    #[cfg(feature = "cram-md5")]
        {
            use crate::mechanisms::cram_md5::mechinfo::gsasl_cram_md5_mechanism;
            let rc = gsasl_register(ctx, &mut gsasl_cram_md5_mechanism);
            if rc != GSASL_OK as libc::c_int { return rc }
        }


    #[cfg(feature = "scram-sha-1")]
        {
            use crate::mechanisms::scram::mechinfo::{gsasl_scram_sha1_mechanism, gsasl_scram_sha1_plus_mechanism};
            let rc = gsasl_register(ctx, &mut gsasl_scram_sha1_mechanism);
            if rc != GSASL_OK as libc::c_int { return rc }

            let rc = gsasl_register(ctx, &mut gsasl_scram_sha1_plus_mechanism);
            if rc != GSASL_OK as libc::c_int { return rc }
        }


    #[cfg(feature = "scram-sha-2")]
        {
            use crate::mechanisms::scram::mechinfo::{gsasl_scram_sha256_mechanism, gsasl_scram_sha256_plus_mechanism};
            let rc = gsasl_register(ctx, &mut gsasl_scram_sha256_mechanism);
            if rc != GSASL_OK as libc::c_int { return rc }

            let rc = gsasl_register(ctx, &mut gsasl_scram_sha256_plus_mechanism);
            if rc != GSASL_OK as libc::c_int { return rc }
        }

    #[cfg(feature = "saml20")]
        {
            use crate::mechanisms::saml20::mechinfo::gsasl_saml20_mechanism;
            let rc = gsasl_register(ctx, &mut gsasl_saml20_mechanism);
            if rc != GSASL_OK as libc::c_int { return rc }
        }


    #[cfg(feature = "openid20")]
        {
            use crate::mechanisms::openid20::mechinfo::gsasl_openid20_mechanism;
            let rc = gsasl_register(ctx, &mut gsasl_openid20_mechanism);
            if rc != GSASL_OK as libc::c_int { return rc }
        }

    /* USE_GSSAPI */
    /* USE_GSSAPI */

    return GSASL_OK as libc::c_int;
}
