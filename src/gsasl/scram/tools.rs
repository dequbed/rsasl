use ::libc;
use crate::gsasl::consts::GSASL_SCRAM_SALTED_PASSWORD;
use crate::gsasl::crypto::gsasl_hash_length;
use crate::gsasl::gsasl::Session;
use crate::gsasl::mechtools::{_gsasl_hex_encode, Gsasl_hash};
use crate::gsasl::property::gsasl_property_set;

/* Hex encode HASHBUF which is HASH digest output and set salted
   password property to the hex encoded value. */
#[no_mangle]
pub unsafe fn set_saltedpassword(mut sctx: *mut Session,
                                 mut hash: Gsasl_hash,
                                 mut hashbuf: *const libc::c_char)
 -> libc::c_int {
    let mut hexstr: [libc::c_char; 65] = [0; 65];
    _gsasl_hex_encode(hashbuf, gsasl_hash_length(hash), hexstr.as_mut_ptr());
    return gsasl_property_set(sctx, GSASL_SCRAM_SALTED_PASSWORD,
                              hexstr.as_mut_ptr());
}
