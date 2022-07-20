use crate::gsasl::consts::GSASL_OK;
use crate::gsasl::gl::free::rpl_free;
use crate::gsasl::gl::gc_gnulib::gc_nonce;
use crate::gsasl::mechtools::{
    Gsasl_hash, _gsasl_hash, _gsasl_hmac, _gsasl_pbkdf2, GSASL_HASH_SHA1_SIZE,
    GSASL_HASH_SHA256_SIZE,
};
use ::libc;
use libc::{size_t, strlen};

pub unsafe fn gsasl_nonce(mut data: *mut libc::c_char, mut datalen: size_t) -> libc::c_int {
    return gc_nonce(data, datalen) as libc::c_int;
}

pub unsafe fn gsasl_hash_length(mut hash: Gsasl_hash) -> size_t {
    match hash as libc::c_uint {
        2 => return GSASL_HASH_SHA1_SIZE as libc::c_int as size_t,
        3 => return GSASL_HASH_SHA256_SIZE as libc::c_int as size_t,
        _ => {}
    }
    return 0 as libc::c_int as size_t;
}

#[cfg(any(feature = "scram-sha-2", feature = "scram-sha-1"))]
pub unsafe fn gsasl_scram_secrets_from_salted_password(
    mut hash: Gsasl_hash,
    mut salted_password: *const libc::c_char,
    mut client_key: *mut libc::c_char,
    mut server_key: *mut libc::c_char,
    mut stored_key: *mut libc::c_char,
) -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut hashlen: size_t = gsasl_hash_length(hash);
    /* ClientKey */
    res = _gsasl_hmac(
        hash,
        salted_password,
        hashlen,
        b"Client Key\x00" as *const u8 as *const libc::c_char,
        strlen(b"Client Key\x00" as *const u8 as *const libc::c_char) as usize,
        client_key,
    );
    if res != GSASL_OK as libc::c_int {
        return res;
    }
    /* StoredKey */
    res = _gsasl_hash(hash, client_key, hashlen, stored_key);
    if res != GSASL_OK as libc::c_int {
        return res;
    }
    /* ServerKey */
    res = _gsasl_hmac(
        hash,
        salted_password,
        hashlen,
        b"Server Key\x00" as *const u8 as *const libc::c_char,
        strlen(b"Server Key\x00" as *const u8 as *const libc::c_char) as usize,
        server_key,
    );
    if res != GSASL_OK as libc::c_int {
        return res;
    }
    return GSASL_OK as libc::c_int;
}

#[cfg(any(feature = "scram-sha-2", feature = "scram-sha-1"))]
pub unsafe fn gsasl_scram_secrets_from_password(
    mut hash: Gsasl_hash,
    mut password: *const libc::c_char,
    mut iteration_count: libc::c_uint,
    mut salt: *const libc::c_char,
    mut saltlen: size_t,
    mut salted_password: *mut libc::c_char,
    mut client_key: *mut libc::c_char,
    mut server_key: *mut libc::c_char,
    mut stored_key: *mut libc::c_char,
) -> libc::c_int {
    use crate::gsasl::saslprep::{gsasl_saslprep, GSASL_ALLOW_UNASSIGNED};
    let mut res: libc::c_int = 0;
    let mut preppass: *mut libc::c_char = 0 as *mut libc::c_char;
    res = gsasl_saslprep(
        password,
        GSASL_ALLOW_UNASSIGNED,
        &mut preppass,
        0 as *mut libc::c_int,
    );
    if res != GSASL_OK as libc::c_int {
        return res;
    }
    res = _gsasl_pbkdf2(
        hash,
        preppass,
        strlen(preppass) as usize,
        salt,
        saltlen,
        iteration_count,
        salted_password,
        0 as libc::c_int as size_t,
    );
    rpl_free(preppass as *mut libc::c_void);
    if res != GSASL_OK as libc::c_int {
        return res;
    }
    return gsasl_scram_secrets_from_salted_password(
        hash,
        salted_password,
        client_key,
        server_key,
        stored_key,
    );
}
