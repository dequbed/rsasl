use std::ptr::NonNull;
use ::libc;
use libc::size_t;
use crate::gsasl::base64::gsasl_base64_to;
use crate::gsasl::consts::{GSASL_AUTHENTICATION_ERROR, GSASL_AUTHID, GSASL_AUTHZID, GSASL_CRYPTO_ERROR, GSASL_DIGEST_MD5_HASHED_PASSWORD, GSASL_INTEGRITY_ERROR, GSASL_MALLOC_ERROR, GSASL_MECHANISM_CALLED_TOO_MANY_TIMES, GSASL_MECHANISM_PARSE_ERROR, GSASL_NEEDS_MORE, GSASL_NO_PASSWORD, GSASL_OK, GSASL_PASSWORD, GSASL_QOPS, GSASL_REALM};
use crate::gsasl::crypto::gsasl_nonce;
use crate::mechanisms::digest_md5::digesthmac::digest_md5_hmac;
use crate::mechanisms::digest_md5::free::{digest_md5_free_challenge, digest_md5_free_finish, digest_md5_free_response};
use crate::mechanisms::digest_md5::nonascii::{latin1toutf8, utf8tolatin1ifpossible};
use crate::mechanisms::digest_md5::parser::{digest_md5_challenge, digest_md5_finish, digest_md5_parse_response, digest_md5_response};
use crate::mechanisms::digest_md5::printer::{digest_md5_print_challenge, digest_md5_print_finish};
use crate::mechanisms::digest_md5::qop::{DIGEST_MD5_QOP_AUTH, DIGEST_MD5_QOP_AUTH_CONF, digest_md5_qopstr2qops};
use crate::mechanisms::digest_md5::session::{digest_md5_decode, digest_md5_encode};
use crate::mechanisms::digest_md5::validate::digest_md5_validate;
use crate::gsasl::gc::GC_OK;
use crate::gsasl::gl::gc_gnulib::gc_md5;
use crate::gsasl::property::{gsasl_property_get, gsasl_property_set};
use crate::{Shared, SessionData};

extern "C" {
    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char,
                _: ...) -> libc::c_int;
    fn malloc(_: size_t) -> *mut libc::c_void;
    fn calloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn rpl_free(ptr: *mut libc::c_void);
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> size_t;
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _Gsasl_digest_md5_server_state {
    pub step: libc::c_int,
    pub readseqnum: size_t,
    pub sendseqnum: size_t,
    pub secret: [libc::c_char; 16],
    pub kic: [libc::c_char; 16],
    pub kcc: [libc::c_char; 16],
    pub kis: [libc::c_char; 16],
    pub kcs: [libc::c_char; 16],
    pub challenge: digest_md5_challenge,
    pub response: digest_md5_response,
    pub finish: digest_md5_finish,
}

pub unsafe fn _gsasl_digest_md5_server_start(_sctx: &Shared,
                                             mech_data: &mut Option<NonNull<()>>,
) -> libc::c_int
{
    let mut state: *mut _Gsasl_digest_md5_server_state =
        0 as *mut _Gsasl_digest_md5_server_state;
    let mut nonce: [libc::c_char; 16] = [0; 16];
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut rc: libc::c_int = 0;
    rc = gsasl_nonce(nonce.as_mut_ptr(), 16);
    if rc != GSASL_OK as libc::c_int { return rc }
    rc =
        gsasl_base64_to(nonce.as_mut_ptr(), 16,
                        &mut p, 0 as *mut size_t);
    if rc != GSASL_OK as libc::c_int { return rc }
    state =
        calloc(1, ::std::mem::size_of::<_Gsasl_digest_md5_server_state>())
            as *mut _Gsasl_digest_md5_server_state;
    if state.is_null() {
        rpl_free(p as *mut libc::c_void);
        return GSASL_MALLOC_ERROR as libc::c_int
    }
    (*state).challenge.qops = DIGEST_MD5_QOP_AUTH as libc::c_int;
    (*state).challenge.ciphers = 0 as libc::c_int;
    (*state).challenge.nonce = p;
    (*state).challenge.utf8 = 1 as libc::c_int;
    *mech_data = NonNull::new(state as *mut ());
    return GSASL_OK as libc::c_int;
}
unsafe fn _gsasl_digest_md5_hexdigit_to_char(mut hexdigit:
                                                            libc::c_char)
 -> libc::c_char {
    /* The hex representation always contains lowercase alphabetic
     characters.  See RFC 2831, 1.1. */
    if hexdigit as libc::c_int >= '0' as i32 &&
           hexdigit as libc::c_int <= '9' as i32 {
        return (hexdigit as libc::c_int - '0' as i32) as libc::c_char
    }
    if hexdigit as libc::c_int >= 'a' as i32 &&
           hexdigit as libc::c_int <= 'z' as i32 {
        return (hexdigit as libc::c_int - 'a' as i32 + 10 as libc::c_int) as
                   libc::c_char
    }
    return -(1 as libc::c_int) as libc::c_char;
}
unsafe fn _gsasl_digest_md5_hex_to_char(mut u: libc::c_char,
                                                   mut l: libc::c_char)
 -> libc::c_char {
    return (_gsasl_digest_md5_hexdigit_to_char(u) as libc::c_uchar as
                libc::c_int * 16 as libc::c_int +
                _gsasl_digest_md5_hexdigit_to_char(l) as libc::c_int) as
               libc::c_char;
}
unsafe fn _gsasl_digest_md5_set_hashed_secret(mut secret:
                                                             *mut libc::c_char,
                                                         mut hex_secret:
                                                             *const libc::c_char)
 -> libc::c_int {
    /* Convert the hex string containing the secret to a byte array */
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    if hex_secret.is_null() {
        return GSASL_AUTHENTICATION_ERROR as libc::c_int
    }
    s = secret;
    p = hex_secret;
    while *p != 0 {
        *s =
            _gsasl_digest_md5_hex_to_char(*p.offset(0 as libc::c_int as
                                                        isize),
                                          *p.offset(1 as libc::c_int as
                                                        isize));
        s = s.offset(1);
        p = p.offset(2 as libc::c_int as isize)
    }
    return GSASL_OK as libc::c_int;
}

pub unsafe fn _gsasl_digest_md5_server_step(sctx: &mut SessionData,
                                            mech_data: Option<NonNull<()>>,
                                            input: Option<&[u8]>,
                                            output: *mut *mut libc::c_char,
                                            output_len: *mut size_t,
)
 -> libc::c_int {
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);

    let input_len = input.map(|i| i.len()).unwrap_or(0);
    let input: *const libc::c_char = input.map(|i| i.as_ptr().cast()).unwrap_or(std::ptr::null());


    let mut state: *mut _Gsasl_digest_md5_server_state =
        mech_data as *mut _Gsasl_digest_md5_server_state;
    let mut rc: libc::c_int = 0;
    let mut res: libc::c_int = 0;
    *output = 0 as *mut libc::c_char;
    *output_len = 0 as libc::c_int as size_t;
    match (*state).step {
        0 => {
            /* Set realm. */
            let mut c: *const libc::c_char = 0 as *const libc::c_char;
            c = gsasl_property_get(sctx, GSASL_REALM);
            if !c.is_null() {
                (*state).challenge.nrealms = 1 as libc::c_int as size_t;
                (*state).challenge.realms =
                    malloc(::std::mem::size_of::<*mut libc::c_char>()) as *mut *mut libc::c_char;
                if (*state).challenge.realms.is_null() {
                    return GSASL_MALLOC_ERROR as libc::c_int
                }
                let ref mut fresh0 =
                    *(*state).challenge.realms.offset(0 as libc::c_int as
                                                          isize);
                *fresh0 = strdup(c);
                if (*(*state).challenge.realms.offset(0 as libc::c_int as
                                                          isize)).is_null() {
                    return GSASL_MALLOC_ERROR as libc::c_int
                }
            }
            /* Set QOP */
            let mut qopstr: *const libc::c_char =
                gsasl_property_get(sctx, GSASL_QOPS);
            if !qopstr.is_null() {
                let mut qops: libc::c_int = digest_md5_qopstr2qops(qopstr);
                if qops == -(1 as libc::c_int) {
                    return GSASL_MALLOC_ERROR as libc::c_int
                }
                /* We don't support confidentiality right now. */
                if qops & DIGEST_MD5_QOP_AUTH_CONF as libc::c_int != 0 {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
                if qops != 0 { (*state).challenge.qops = qops }
            }
            /* FIXME: cipher, maxbuf, more realms. */
            /* Create challenge. */
            *output = digest_md5_print_challenge(&mut (*state).challenge);
            if (*output).is_null() {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            *output_len = strlen(*output);
            (*state).step += 1;
            res = GSASL_NEEDS_MORE as libc::c_int
        }
        1 => {
            if digest_md5_parse_response(input, input_len,
                                         &mut (*state).response) <
                   0 as libc::c_int {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            /* Make sure response is consistent with challenge. */
            if digest_md5_validate(&mut (*state).challenge,
                                   &mut (*state).response) < 0 as libc::c_int
               {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            /* Store properties, from the client response. */
            if (*state).response.utf8 != 0 {
                res =
                    gsasl_property_set(sctx, GSASL_AUTHID,
                                       (*state).response.username);
                if res != GSASL_OK as libc::c_int { return res }
                res =
                    gsasl_property_set(sctx, GSASL_REALM,
                                       (*state).response.realm);
                if res != GSASL_OK as libc::c_int { return res }
            } else {
                /* Client provided username/realm in ISO-8859-1 form,
	     convert it to UTF-8 since the library is all-UTF-8. */
                let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
                tmp = latin1toutf8((*state).response.username);
                if tmp.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
                res = gsasl_property_set(sctx, GSASL_AUTHID, tmp);
                rpl_free(tmp as *mut libc::c_void);
                if res != GSASL_OK as libc::c_int { return res }
                tmp = latin1toutf8((*state).response.realm);
                if tmp.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
                res = gsasl_property_set(sctx, GSASL_REALM, tmp);
                rpl_free(tmp as *mut libc::c_void);
                if res != GSASL_OK as libc::c_int { return res }
            }
            res =
                gsasl_property_set(sctx, GSASL_AUTHZID,
                                   (*state).response.authzid);
            if res != GSASL_OK as libc::c_int { return res }
            /* FIXME: cipher, maxbuf.  */
            /* Compute secret. */
            let mut passwd: *const libc::c_char = 0 as *const libc::c_char;
            let mut hashed_passwd: *const libc::c_char =
                0 as *const libc::c_char;
            hashed_passwd =
                gsasl_property_get(sctx, GSASL_DIGEST_MD5_HASHED_PASSWORD);
            if !hashed_passwd.is_null() {
                if strlen(hashed_passwd) != (16 * 2) {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
                rc =
                    _gsasl_digest_md5_set_hashed_secret((*state).secret.as_mut_ptr(),
                                                        hashed_passwd);
                if rc != GSASL_OK as libc::c_int { return rc }
            } else {
                passwd = gsasl_property_get(sctx, GSASL_PASSWORD);
                if !passwd.is_null() {
                    let mut tmp_0: *mut libc::c_char = 0 as *mut libc::c_char;
                    let mut tmp2: *mut libc::c_char = 0 as *mut libc::c_char;
                    tmp2 = utf8tolatin1ifpossible(passwd);
                    rc =
                        asprintf(&mut tmp_0 as *mut *mut libc::c_char,
                                 b"%s:%s:%s\x00" as *const u8 as
                                     *const libc::c_char,
                                 (*state).response.username,
                                 if !(*state).response.realm.is_null() {
                                     (*state).response.realm
                                 } else {
                                     b"\x00" as *const u8 as
                                         *const libc::c_char
                                 }, tmp2);
                    rpl_free(tmp2 as *mut libc::c_void);
                    if rc < 0 as libc::c_int {
                        return GSASL_MALLOC_ERROR as libc::c_int
                    }
                    rc =
                        gc_md5(tmp_0 as *const libc::c_void, strlen(tmp_0),
                               (*state).secret.as_mut_ptr() as
                                   *mut libc::c_void) as libc::c_int;
                    rpl_free(tmp_0 as *mut libc::c_void);
                    if rc != GC_OK as libc::c_int {
                        return GSASL_CRYPTO_ERROR as libc::c_int
                    }
                } else { return GSASL_NO_PASSWORD as libc::c_int }
            }
            /* Check client response. */
            let mut check: [libc::c_char; 33] = [0; 33];
            rc =
                digest_md5_hmac(check.as_mut_ptr(),
                                (*state).secret.as_mut_ptr(),
                                (*state).response.nonce, (*state).response.nc,
                                (*state).response.cnonce,
                                (*state).response.qop,
                                (*state).response.authzid,
                                (*state).response.digesturi, 0 as libc::c_int,
                                (*state).response.cipher,
                                (*state).kic.as_mut_ptr(),
                                (*state).kis.as_mut_ptr(),
                                (*state).kcc.as_mut_ptr(),
                                (*state).kcs.as_mut_ptr());
            if rc != 0 { return GSASL_AUTHENTICATION_ERROR as libc::c_int }
            if strcmp((*state).response.response.as_mut_ptr(),
                      check.as_mut_ptr()) != 0 as libc::c_int {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            /* Create finish token. */
            rc =
                digest_md5_hmac((*state).finish.rspauth.as_mut_ptr(),
                                (*state).secret.as_mut_ptr(),
                                (*state).response.nonce, (*state).response.nc,
                                (*state).response.cnonce,
                                (*state).response.qop,
                                (*state).response.authzid,
                                (*state).response.digesturi, 1 as libc::c_int,
                                (*state).response.cipher,
                                0 as *mut libc::c_char,
                                0 as *mut libc::c_char,
                                0 as *mut libc::c_char,
                                0 as *mut libc::c_char);
            if rc != 0 { return GSASL_AUTHENTICATION_ERROR as libc::c_int }
            *output = digest_md5_print_finish(&mut (*state).finish);
            if (*output).is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            *output_len = strlen(*output);
            (*state).step += 1;
            res = GSASL_OK as libc::c_int
        }
        _ => { res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int }
    }
    return res;
}

pub unsafe fn _gsasl_digest_md5_server_finish(mech_data: Option<NonNull<()>>)
{
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);
    let mut state: *mut _Gsasl_digest_md5_server_state =
        mech_data as *mut _Gsasl_digest_md5_server_state;
    if state.is_null() { return }
    digest_md5_free_challenge(&mut (*state).challenge);
    digest_md5_free_response(&mut (*state).response);
    digest_md5_free_finish(&mut (*state).finish);
    rpl_free(state as *mut libc::c_void);
}

pub unsafe fn _gsasl_digest_md5_server_encode(mut _sctx: &mut SessionData,
                                              mut mech_data: Option<NonNull<()>>,
                                              mut input: *const libc::c_char,
                                              mut input_len: size_t,
                                              mut output: *mut *mut libc::c_char,
                                              mut output_len: *mut size_t,
) -> libc::c_int
{
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);

    let mut state: *mut _Gsasl_digest_md5_server_state =
        mech_data as *mut _Gsasl_digest_md5_server_state;
    let mut res: libc::c_int = 0;
    res =
        digest_md5_encode(input, input_len, output, output_len,
                          (*state).response.qop, (*state).sendseqnum,
                          (*state).kis.as_mut_ptr());
    if res != 0 {
        return if res == -(2 as libc::c_int) {
                   GSASL_NEEDS_MORE as libc::c_int
               } else { GSASL_INTEGRITY_ERROR as libc::c_int }
    }
    if (*state).sendseqnum == 4294967295 {
        (*state).sendseqnum = 0
    } else { (*state).sendseqnum = (*state).sendseqnum.wrapping_add(1) }
    return GSASL_OK as libc::c_int;
}
/* digest-md5.h --- Prototypes for DIGEST-MD5 mechanism as defined in RFC 2831.
 * Copyright (C) 2002-2021 Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */
pub unsafe fn _gsasl_digest_md5_server_decode(mut _sctx: &mut SessionData,
                                              mech_data: Option<NonNull<()>>,
                                              mut input: *const libc::c_char,
                                              mut input_len: size_t,
                                              mut output: *mut *mut libc::c_char,
                                              mut output_len: *mut size_t,
) -> libc::c_int
{
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);

    let mut state: *mut _Gsasl_digest_md5_server_state =
        mech_data as *mut _Gsasl_digest_md5_server_state;
    let mut res: libc::c_int = 0;
    res =
        digest_md5_decode(input, input_len, output, output_len,
                          (*state).response.qop, (*state).readseqnum,
                          (*state).kic.as_mut_ptr());
    if res != 0 {
        return if res == -(2 as libc::c_int) {
                   GSASL_NEEDS_MORE as libc::c_int
               } else { GSASL_INTEGRITY_ERROR as libc::c_int }
    }
    if (*state).readseqnum == 4294967295 {
        (*state).readseqnum = 0
    } else { (*state).readseqnum = (*state).readseqnum.wrapping_add(1) }
    return GSASL_OK as libc::c_int;
}
