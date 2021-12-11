use ::libc;
use crate::gsasl::anonymous::mechinfo::gsasl_anonymous_mechanism;
use crate::gsasl::consts::{GSASL_CRYPTO_ERROR, GSASL_MALLOC_ERROR, GSASL_OK};
use crate::gsasl::cram_md5::mechinfo::gsasl_cram_md5_mechanism;
use crate::gsasl::digest_md5::mechinfo::gsasl_digest_md5_mechanism;
use crate::gsasl::done::gsasl_done;
use crate::gsasl::external::mechinfo::gsasl_external_mechanism;
use crate::gsasl::gc::GC_OK;
use crate::gsasl::gsasl::{Gsasl};
use crate::gsasl::login::mechinfo::gsasl_login_mechanism;
use crate::gsasl::openid20::mechinfo::gsasl_openid20_mechanism;
use crate::gsasl::plain::mechinfo::gsasl_plain_mechanism;
use crate::gsasl::register::gsasl_register;
use crate::gsasl::saml20::mechinfo::gsasl_saml20_mechanism;
use crate::gsasl::scram::mechinfo::{gsasl_scram_sha1_mechanism, gsasl_scram_sha1_plus_mechanism, gsasl_scram_sha256_mechanism, gsasl_scram_sha256_plus_mechanism};
use crate::gsasl::securid::mechinfo::gsasl_securid_mechanism;

extern "C" {
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
}

#[no_mangle]
pub static mut GSASL_VALID_MECHANISM_CHARACTERS: *const libc::c_char =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_\x00" as *const u8 as
        *const libc::c_char;

pub unsafe fn register_builtin_mechs(ctx: &mut Gsasl) -> libc::c_int {
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
    rc = gsasl_register(ctx, &mut gsasl_plain_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
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
