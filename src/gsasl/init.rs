use ::libc;
use crate::{CMechBuilder, Shared};
use crate::mechanisms::anonymous::mechinfo::gsasl_anonymous_mechanism;
use crate::gsasl::consts::GSASL_OK;
use crate::mechanisms::cram_md5::mechinfo::gsasl_cram_md5_mechanism;
use crate::mechanisms::digest_md5::mechinfo::gsasl_digest_md5_mechanism;
use crate::mechanisms::external::mechinfo::gsasl_external_mechanism;
use crate::mechanisms::login::mechinfo::gsasl_login_mechanism;
use crate::mechanisms::openid20::mechinfo::gsasl_openid20_mechanism;
use crate::mechanisms::plain::client::Plain;
use crate::mechanisms::plain::mechinfo::gsasl_plain_mechanism;
use crate::gsasl::register::gsasl_register;
use crate::mechanism::MechanismInstance;
use crate::mechanisms::saml20::mechinfo::gsasl_saml20_mechanism;
use crate::mechanisms::scram::mechinfo::{gsasl_scram_sha1_mechanism,
                                        gsasl_scram_sha1_plus_mechanism,
                                gsasl_scram_sha256_mechanism, gsasl_scram_sha256_plus_mechanism};
use crate::mechanisms::securid::mechinfo::gsasl_securid_mechanism;
use crate::mechname::Mechanism;
use crate::registry::DynamicRegistry;

extern "C" {
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
}

#[no_mangle]
pub static mut GSASL_VALID_MECHANISM_CHARACTERS: *const libc::c_char =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_\x00" as *const u8 as
        *const libc::c_char;

pub(crate) unsafe fn register_builtin_mechs(ctx: &mut DynamicRegistry) -> libc::c_int {
    let mut rc: libc::c_int = GSASL_OK as libc::c_int;
    rc = gsasl_register(ctx, &mut gsasl_anonymous_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_ANONYMOUS */
    rc = gsasl_register(ctx, &mut gsasl_external_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_EXTERNAL */
    rc = gsasl_register(ctx, &mut gsasl_login_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_LOGIN */
    ctx.register(Mechanism::new("PLAIN"), Plain, CMechBuilder {
        name: Mechanism::new("PLAIN"),
        vtable: gsasl_plain_mechanism.server
    });
    /*rc = gsasl_register(ctx, &mut gsasl_plain_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }*/
    /* USE_PLAIN */
    rc = gsasl_register(ctx, &mut gsasl_securid_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_SECURID */
    /* USE_NTLM */
    rc = gsasl_register(ctx, &mut gsasl_digest_md5_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_DIGEST_MD5 */
    rc = gsasl_register(ctx, &mut gsasl_cram_md5_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_CRAM_MD5 */
    rc = gsasl_register(ctx, &mut gsasl_scram_sha1_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    rc = gsasl_register(ctx, &mut gsasl_scram_sha1_plus_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_SCRAM_SHA1 */
    rc = gsasl_register(ctx, &mut gsasl_scram_sha256_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    rc = gsasl_register(ctx, &mut gsasl_scram_sha256_plus_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_SCRAM_SHA256 */
    rc = gsasl_register(ctx, &mut gsasl_saml20_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_SAML20 */
    rc = gsasl_register(ctx, &mut gsasl_openid20_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_OPENID20 */
    /* USE_GSSAPI */
    /* USE_GSSAPI */
    return GSASL_OK as libc::c_int;
}
