use std::ptr::NonNull;
use ::libc;
use libc::size_t;
use crate::gsasl::base64::{gsasl_base64_from, gsasl_base64_to};
use crate::gsasl::consts::{GSASL_AUTHENTICATION_ERROR, GSASL_AUTHID, GSASL_AUTHZID, GSASL_CB_TLS_UNIQUE, GSASL_MALLOC_ERROR, GSASL_MECHANISM_CALLED_TOO_MANY_TIMES, GSASL_MECHANISM_PARSE_ERROR, GSASL_NEEDS_MORE, GSASL_NO_CB_TLS_UNIQUE, GSASL_NO_PASSWORD, GSASL_OK, GSASL_PASSWORD, GSASL_SCRAM_ITER, GSASL_SCRAM_SALT, GSASL_SCRAM_SERVERKEY, GSASL_SCRAM_STOREDKEY};
use crate::gsasl::crypto::{gsasl_hash_length, gsasl_nonce, gsasl_scram_secrets_from_password};
use crate::gsasl::free::gsasl_free;
use crate::gsasl::mechtools::{_gsasl_hash, _gsasl_hmac, Gsasl_hash, GSASL_HASH_SHA1, GSASL_HASH_SHA256};
use crate::gsasl::property::{gsasl_property_get, gsasl_property_set};
use crate::gsasl::saslprep::{GSASL_ALLOW_UNASSIGNED, gsasl_saslprep};
use crate::mechanisms::scram::client::{scram_client_final, scram_client_first};
use crate::mechanisms::scram::parser::{scram_parse_client_final, scram_parse_client_first};
use crate::mechanisms::scram::printer::{scram_print_server_final, scram_print_server_first};
use crate::mechanisms::scram::tokens::{scram_free_client_final, scram_free_client_first, scram_free_server_final, scram_free_server_first};
use crate::mechanisms::scram::tools::set_saltedpassword;
use crate::{Shared, SessionData};

extern "C" {
    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char,
                _: ...) -> libc::c_int;

    fn strtoul(_: *const libc::c_char, _: *mut *mut libc::c_char,
               _: libc::c_int) -> size_t;

    fn malloc(_: size_t) -> *mut libc::c_void;

    fn calloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn rpl_free(ptr: *mut libc::c_void);

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: size_t)
     -> *mut libc::c_void;

    fn memcmp(_: *const libc::c_void, _: *const libc::c_void,
              _: size_t) -> libc::c_int;

    fn memchr(_: *const libc::c_void, _: libc::c_int, _: size_t)
     -> *mut libc::c_void;

    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;

    fn memmem(__haystack: *const libc::c_void, __haystacklen: size_t,
              __needle: *const libc::c_void, __needlelen: size_t)
     -> *mut libc::c_void;

    fn strlen(_: *const libc::c_char) -> size_t;
    fn memxor(dest: *mut libc::c_void, src: *const libc::c_void, n: size_t)
     -> *mut libc::c_void;
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_server_state {
    pub plus: bool,
    pub hash: Gsasl_hash,
    pub step: libc::c_int,
    pub cbind: *mut libc::c_char,
    pub gs2header: *mut libc::c_char,
    pub cfmb_str: *mut libc::c_char,
    pub sf_str: *mut libc::c_char,
    pub snonce: *mut libc::c_char,
    pub clientproof: *mut libc::c_char,
    pub storedkey: [libc::c_char; 32],
    pub serverkey: [libc::c_char; 32],
    pub authmessage: *mut libc::c_char,
    pub cbtlsunique: *mut libc::c_char,
    pub cbtlsuniquelen: size_t,
    pub cf: scram_client_first,
    pub sf: scram_server_first,
    pub cl: scram_client_final,
    pub sl: scram_server_final,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_server_final {
    pub verifier: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_server_first {
    pub nonce: *mut libc::c_char,
    pub salt: *mut libc::c_char,
    pub iter: size_t,
}

/* tokens.h --- Types for SCRAM tokens.
 * Copyright (C) 2009-2021 Simon Josefsson
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
/* Get size_t. */
unsafe fn scram_start(
    mut _sctx: &Shared,
    mut mech_data: *mut *mut libc::c_void,
    mut plus: bool, mut hash: Gsasl_hash,
)
    -> libc::c_int {
    let mut state: *mut scram_server_state = 0 as *mut scram_server_state;
    let mut buf: [libc::c_char; 18] = [0; 18];
    let mut rc: libc::c_int = 0;
    state = calloc(::std::mem::size_of::<scram_server_state>(), 1) as *mut scram_server_state;
    if state.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    (*state).plus = plus;
    (*state).hash = hash;
    rc = gsasl_nonce(buf.as_mut_ptr(), 18 as libc::c_int as size_t);
    if !(rc != GSASL_OK as libc::c_int) {
        rc =
            gsasl_base64_to(buf.as_mut_ptr(), 18 as libc::c_int as size_t,
                            &mut (*state).snonce, 0 as *mut size_t);
        if !(rc != GSASL_OK as libc::c_int) {
            rc = gsasl_nonce(buf.as_mut_ptr(), 12 as libc::c_int as size_t);
            if !(rc != GSASL_OK as libc::c_int) {
                rc =
                    gsasl_base64_to(buf.as_mut_ptr(),
                                    12 as libc::c_int as size_t,
                                    &mut (*state).sf.salt, 0 as *mut size_t);
                if !(rc != GSASL_OK as libc::c_int) {
                    *mech_data = state as *mut libc::c_void;
                    return GSASL_OK as libc::c_int
                }
            }
        }
    }
    rpl_free((*state).sf.salt as *mut libc::c_void);
    rpl_free((*state).snonce as *mut libc::c_void);
    rpl_free(state as *mut libc::c_void);
    return rc;
}

pub(crate) unsafe fn _gsasl_scram_sha1_server_start(mut sctx: &Shared,
                                             mut mech_data: &mut Option<NonNull<()>>,
) -> libc::c_int
{
    let mut ptr = mech_data
        .map(|ptr| ptr.as_ptr().cast())
        .unwrap_or_else(std::ptr::null_mut);

    let ret = scram_start(sctx,
                          &mut ptr,
                          0 as libc::c_int != 0,
                          GSASL_HASH_SHA1);

    *mech_data = NonNull::new(ptr.cast());

    return ret;
}

pub(crate) unsafe fn _gsasl_scram_sha1_plus_server_start(sctx: &Shared,
                                                  mech_data: &mut Option<NonNull<()>>,
) -> libc::c_int
{
    let mut ptr = mech_data
        .map(|ptr| ptr.as_ptr().cast())
        .unwrap_or_else(std::ptr::null_mut);

    let ret = scram_start(sctx,
                          &mut ptr,
                          1 as libc::c_int != 0,
                       GSASL_HASH_SHA1);

    *mech_data = NonNull::new(ptr.cast());

    return ret;
}

pub(crate) unsafe fn _gsasl_scram_sha256_server_start(sctx: &Shared,
                                               mech_data: &mut Option<NonNull<()>>,
) -> libc::c_int
{
    let mut ptr = mech_data
        .map(|ptr| ptr.as_ptr().cast())
        .unwrap_or_else(std::ptr::null_mut);

    let ret = scram_start(sctx,
                          &mut ptr,
                          0 as libc::c_int != 0,
                       GSASL_HASH_SHA256);

    *mech_data = NonNull::new(ptr.cast());

    return ret;
}

pub(crate) unsafe fn _gsasl_scram_sha256_plus_server_start(sctx: &Shared,
                                                    mech_data: &mut Option<NonNull<()>>,
) -> libc::c_int
{
    let mut ptr = mech_data
        .map(|ptr| ptr.as_ptr().cast())
        .unwrap_or_else(std::ptr::null_mut);

    let ret = scram_start(sctx,
                       &mut ptr,
                       1 as libc::c_int != 0,
                       GSASL_HASH_SHA256);

    *mech_data = NonNull::new(ptr.cast());

    return ret;
}

unsafe fn extract_serverkey(mut state: *mut scram_server_state,
                                       mut b64: *const libc::c_char,
                                       mut buf: *mut libc::c_char)
 -> libc::c_int {
    let mut bin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut binlen: size_t = 0;
    let mut rc: libc::c_int = 0;
    rc = gsasl_base64_from(b64, strlen(b64), &mut bin, &mut binlen);
    if rc != GSASL_OK as libc::c_int { return rc }
    if binlen != gsasl_hash_length((*state).hash) {
        rpl_free(bin as *mut libc::c_void);
        return GSASL_AUTHENTICATION_ERROR as libc::c_int
    }
    memcpy(buf as *mut libc::c_void, bin as *const libc::c_void, binlen);
    rpl_free(bin as *mut libc::c_void);
    return GSASL_OK as libc::c_int;
}

pub unsafe fn _gsasl_scram_server_step(sctx: &mut SessionData,
                                       mech_data: Option<NonNull<()>>,
                                       input: Option<&[u8]>,
                                       output: *mut *mut libc::c_char,
                                       output_len: *mut size_t,
) -> libc::c_int
{
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);

    let input_len = input.map(|i| i.len()).unwrap_or(0);
    let input: *const libc::c_char = input.map(|i| i.as_ptr().cast()).unwrap_or(std::ptr::null());

    let mut state: *mut scram_server_state =
        mech_data as *mut scram_server_state;
    let mut res: libc::c_int =
        GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int;
    let mut rc: libc::c_int = 0;
    *output = 0 as *mut libc::c_char;
    *output_len = 0 as libc::c_int as size_t;
    match (*state).step {
        0 => {
            if input_len == 0 {
                return GSASL_NEEDS_MORE as libc::c_int
            }
            let mut p: *const libc::c_char = 0 as *const libc::c_char;
            p = gsasl_property_get(sctx, GSASL_CB_TLS_UNIQUE);
            if (*state).plus as libc::c_int != 0 && p.is_null() {
                return GSASL_NO_CB_TLS_UNIQUE as libc::c_int
            }
            if !p.is_null() {
                rc =
                    gsasl_base64_from(p, strlen(p), &mut (*state).cbtlsunique,
                                      &mut (*state).cbtlsuniquelen);
                if rc != GSASL_OK as libc::c_int { return rc }
            }
            if scram_parse_client_first(input, input_len, &mut (*state).cf) <
                   0 as libc::c_int {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            /* In PLUS server mode, we require use of channel bindings. */
            if (*state).plus as libc::c_int != 0
                && (*state).cf.cbflag as libc::c_int != 'p' as i32
            {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            /* In non-PLUS mode, but where have channel bindings data (and
	   thus advertised PLUS) we reject a client 'y' cbflag. */
            if !(*state).plus
                && (*state).cbtlsuniquelen > 0
                && (*state).cf.cbflag as libc::c_int == 'y' as i32
            {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            /* Check that username doesn't fail SASLprep. */
            let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
            rc = gsasl_saslprep((*state).cf.username, GSASL_ALLOW_UNASSIGNED,
                                &mut tmp, 0 as *mut libc::c_int);
            if rc != GSASL_OK as libc::c_int ||
                   *tmp as libc::c_int == '\u{0}' as i32 {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            gsasl_free(tmp as *mut libc::c_void);
            let mut p_0: *const libc::c_char = 0 as *const libc::c_char;
            /* Save "gs2-header" and "message-bare" for next step. */
            p_0 =
                memchr(input as *const libc::c_void, ',' as i32, input_len) as
                    *const libc::c_char;
            if p_0.is_null() {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            p_0 = p_0.offset(1);
            p_0 =
                memchr(p_0 as *const libc::c_void, ',' as i32,
                       input_len.wrapping_sub(p_0.offset_from(input) as usize))
                    as *const libc::c_char;
            if p_0.is_null() {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            p_0 = p_0.offset(1);
            (*state).gs2header =
                malloc((p_0.offset_from(input) + 1) as size_t) as *mut libc::c_char;
            if (*state).gs2header.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            memcpy((*state).gs2header as *mut libc::c_void,
                   input as *const libc::c_void,
                   p_0.offset_from(input) as size_t);
            *(*state).gs2header.offset(p_0.offset_from(input) as
                                           libc::c_long as isize) =
                '\u{0}' as i32 as libc::c_char;
            (*state).cfmb_str = malloc(input_len.wrapping_sub(p_0.offset_from(input) as usize)
                                                .wrapping_add(1))
                as *mut libc::c_char;
            if (*state).cfmb_str.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            memcpy((*state).cfmb_str as *mut libc::c_void,
                   p_0 as *const libc::c_void,
                   input_len.wrapping_sub(p_0.offset_from(input) as usize));
            *(*state).cfmb_str.offset(
                input_len.wrapping_sub(p_0.offset_from(input) as usize)
                                          as isize) =
                '\u{0}' as i32 as libc::c_char;
            /* Create new nonce. */
            let mut cnlen: size_t = strlen((*state).cf.client_nonce);
            let mut snlen: size_t = strlen((*state).snonce);
            (*state).sf.nonce =
                malloc(cnlen.wrapping_add(snlen).wrapping_add(1))
                    as *mut libc::c_char;
            if (*state).sf.nonce.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            memcpy((*state).sf.nonce as *mut libc::c_void,
                   (*state).cf.client_nonce as *const libc::c_void, cnlen);
            memcpy((*state).sf.nonce.offset(cnlen as isize) as
                       *mut libc::c_void,
                   (*state).snonce as *const libc::c_void, snlen);
            *(*state).sf.nonce.offset(cnlen.wrapping_add(snlen) as isize) =
                '\u{0}' as i32 as libc::c_char;
            rc = gsasl_property_set(sctx, GSASL_AUTHID, (*state).cf.username);
            if rc != GSASL_OK as libc::c_int { return rc }
            rc = gsasl_property_set(sctx, GSASL_AUTHZID, (*state).cf.authzid);
            if rc != GSASL_OK as libc::c_int { return rc }
            let mut p_1: *const libc::c_char =
                gsasl_property_get(sctx, GSASL_SCRAM_ITER);
            if !p_1.is_null() {
                (*state).sf.iter =
                    strtoul(p_1, 0 as *mut *mut libc::c_char,
                            10 as libc::c_int)
            }
            if p_1.is_null()
                || (*state).sf.iter == 0
                || (*state).sf.iter == (9223372036854775807 as size_t)
                        .wrapping_mul(2)
                        .wrapping_add(1)
            {
                (*state).sf.iter = 4096 as libc::c_int as size_t
            }
            /* Save salt/iter as properties, so that client callback can
	     access them. */
            let mut str: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut n: libc::c_int = 0;
            n =
                asprintf(&mut str as *mut *mut libc::c_char,
                         b"%zu\x00" as *const u8 as *const libc::c_char,
                         (*state).sf.iter);
            if n < 0 as libc::c_int || str.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            rc = gsasl_property_set(sctx, GSASL_SCRAM_ITER, str);
            rpl_free(str as *mut libc::c_void);
            if rc != GSASL_OK as libc::c_int { return rc }
            let mut p_2: *const libc::c_char =
                gsasl_property_get(sctx, GSASL_SCRAM_SALT);
            if !p_2.is_null() {
                rpl_free((*state).sf.salt as *mut libc::c_void);
                (*state).sf.salt = strdup(p_2)
            } else {
                rc =
                    gsasl_property_set(sctx, GSASL_SCRAM_SALT,
                                       (*state).sf.salt);
                if rc != GSASL_OK as libc::c_int { return rc }
            }
            rc =
                scram_print_server_first(&mut (*state).sf,
                                         &mut (*state).sf_str);
            if rc != 0 as libc::c_int {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            *output = strdup((*state).sf_str);
            if (*output).is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            *output_len = strlen(*output);
            (*state).step += 1;
            return GSASL_NEEDS_MORE as libc::c_int
        }
        1 => {
            if scram_parse_client_final(input, input_len, &mut (*state).cl) <
                   0 as libc::c_int {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            if strcmp((*state).cl.nonce, (*state).sf.nonce) !=
                   0 as libc::c_int {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            /* Base64 decode the c= field and check that it matches
	   client-first.  Also check channel binding data. */
            let mut len: size_t = 0;
            rc =
                gsasl_base64_from((*state).cl.cbind,
                                  strlen((*state).cl.cbind),
                                  &mut (*state).cbind, &mut len);
            if rc != 0 as libc::c_int { return rc }
            if (*state).cf.cbflag as libc::c_int == 'p' as i32 {
                if len < strlen((*state).gs2header) {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
                if memcmp((*state).cbind as *const libc::c_void,
                          (*state).gs2header as *const libc::c_void,
                          strlen((*state).gs2header)) != 0 as libc::c_int {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
                if len.wrapping_sub(strlen((*state).gs2header)) !=
                       (*state).cbtlsuniquelen {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
                if memcmp((*state).cbind.offset(strlen((*state).gs2header) as
                                                    isize) as
                              *const libc::c_void,
                          (*state).cbtlsunique as *const libc::c_void,
                          (*state).cbtlsuniquelen) != 0 as libc::c_int {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
            } else {
                if len != strlen((*state).gs2header) {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
                if memcmp((*state).cbind as *const libc::c_void,
                          (*state).gs2header as *const libc::c_void, len) !=
                       0 as libc::c_int {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
            }
            /* Base64 decode client proof and check that length matches
	   hash size. */
            let mut len_0: size_t = 0;
            rc =
                gsasl_base64_from((*state).cl.proof,
                                  strlen((*state).cl.proof),
                                  &mut (*state).clientproof, &mut len_0);
            if rc != 0 as libc::c_int { return rc }
            if gsasl_hash_length((*state).hash) != len_0 {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            let mut p_3: *const libc::c_char = 0 as *const libc::c_char;
            let mut q: *const libc::c_char = 0 as *const libc::c_char;
            /* Get StoredKey and ServerKey */
            p_3 = gsasl_property_get(sctx, GSASL_SCRAM_SERVERKEY);
            if !p_3.is_null() &&
                   {
                       q = gsasl_property_get(sctx, GSASL_SCRAM_STOREDKEY);
                       !q.is_null()
                   } {
                rc =
                    extract_serverkey(state, p_3,
                                      (*state).serverkey.as_mut_ptr());
                if rc != GSASL_OK as libc::c_int { return rc }
                rc =
                    extract_serverkey(state, q,
                                      (*state).storedkey.as_mut_ptr());
                if rc != GSASL_OK as libc::c_int { return rc }
            } else {
                p_3 = gsasl_property_get(sctx, GSASL_PASSWORD);
                if !p_3.is_null() {
                    let mut salt: *mut libc::c_char = 0 as *mut libc::c_char;
                    let mut saltlen: size_t = 0;
                    let mut saltedpassword: [libc::c_char; 32] = [0; 32];
                    let mut clientkey: [libc::c_char; 32] = [0; 32];
                    let mut b64str: *mut libc::c_char =
                        0 as *mut libc::c_char;
                    rc =
                        gsasl_base64_from((*state).sf.salt,
                                          strlen((*state).sf.salt), &mut salt,
                                          &mut saltlen);
                    if rc != GSASL_OK as libc::c_int { return rc }
                    rc =
                        gsasl_scram_secrets_from_password((*state).hash, p_3,
                                                          (*state).sf.iter as
                                                              libc::c_uint,
                                                          salt, saltlen,
                                                          saltedpassword.as_mut_ptr(),
                                                          clientkey.as_mut_ptr(),
                                                          (*state).serverkey.as_mut_ptr(),
                                                          (*state).storedkey.as_mut_ptr());
                    if rc != GSASL_OK as libc::c_int { return rc }
                    rc =
                        set_saltedpassword(sctx, (*state).hash,
                                           saltedpassword.as_mut_ptr());
                    if rc != GSASL_OK as libc::c_int { return rc }
                    rc =
                        gsasl_base64_to((*state).serverkey.as_mut_ptr(),
                                        gsasl_hash_length((*state).hash),
                                        &mut b64str, 0 as *mut size_t);
                    if rc != GSASL_OK as libc::c_int { return rc }
                    rc =
                        gsasl_property_set(sctx, GSASL_SCRAM_SERVERKEY,
                                           b64str);
                    rpl_free(b64str as *mut libc::c_void);
                    if rc != GSASL_OK as libc::c_int { return rc }
                    rc =
                        gsasl_base64_to((*state).storedkey.as_mut_ptr(),
                                        gsasl_hash_length((*state).hash),
                                        &mut b64str, 0 as *mut size_t);
                    if rc != 0 as libc::c_int { return rc }
                    rc =
                        gsasl_property_set(sctx, GSASL_SCRAM_STOREDKEY,
                                           b64str);
                    rpl_free(b64str as *mut libc::c_void);
                    if rc != GSASL_OK as libc::c_int { return rc }
                    gsasl_free(salt as *mut libc::c_void);
                } else { return GSASL_NO_PASSWORD as libc::c_int }
            }
            /* Compute AuthMessage */
            let mut len_1: size_t = 0;
            let mut n_0: libc::c_int = 0;
            /* Get client-final-message-without-proof. */
            p_3 =
                memmem(input as *const libc::c_void, input_len,
                       b",p=\x00" as *const u8 as *const libc::c_char as
                           *const libc::c_void, 3 as libc::c_int as size_t) as
                    *const libc::c_char;
            if p_3.is_null() {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            len_1 = p_3.offset_from(input) as libc::c_long as size_t;
            n_0 =
                asprintf(&mut (*state).authmessage as *mut *mut libc::c_char,
                         b"%s,%.*s,%.*s\x00" as *const u8 as
                             *const libc::c_char, (*state).cfmb_str,
                         strlen((*state).sf_str) as libc::c_int,
                         (*state).sf_str, len_1 as libc::c_int, input);
            if n_0 <= 0 as libc::c_int || (*state).authmessage.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            /* Check client proof. */
            let mut clientsignature: [libc::c_char; 32] = [0; 32];
            let mut maybe_storedkey: [libc::c_char; 32] = [0; 32];
            /* ClientSignature := HMAC(StoredKey, AuthMessage) */
            rc =
                _gsasl_hmac((*state).hash, (*state).storedkey.as_mut_ptr(),
                            gsasl_hash_length((*state).hash),
                            (*state).authmessage,
                            strlen((*state).authmessage),
                            clientsignature.as_mut_ptr());
            if rc != 0 as libc::c_int { return rc }
            /* ClientKey := ClientProof XOR ClientSignature */
            memxor(clientsignature.as_mut_ptr() as *mut libc::c_void,
                   (*state).clientproof as *const libc::c_void,
                   gsasl_hash_length((*state).hash));
            rc =
                _gsasl_hash((*state).hash, clientsignature.as_mut_ptr(),
                            gsasl_hash_length((*state).hash),
                            maybe_storedkey.as_mut_ptr());
            if rc != 0 as libc::c_int { return rc }
            rc =
                memcmp((*state).storedkey.as_mut_ptr() as *const libc::c_void,
                       maybe_storedkey.as_mut_ptr() as *const libc::c_void,
                       gsasl_hash_length((*state).hash));
            if rc != 0 as libc::c_int {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            /* Generate server verifier. */
            let mut serversignature: [libc::c_char; 32] = [0; 32];
            /* ServerSignature := HMAC(ServerKey, AuthMessage) */
            rc =
                _gsasl_hmac((*state).hash, (*state).serverkey.as_mut_ptr(),
                            gsasl_hash_length((*state).hash),
                            (*state).authmessage,
                            strlen((*state).authmessage),
                            serversignature.as_mut_ptr());
            if rc != 0 as libc::c_int { return rc }
            rc =
                gsasl_base64_to(serversignature.as_mut_ptr(),
                                gsasl_hash_length((*state).hash),
                                &mut (*state).sl.verifier, 0 as *mut size_t);
            if rc != 0 as libc::c_int { return rc }
            rc = scram_print_server_final(&mut (*state).sl, output);
            if rc != 0 as libc::c_int {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            *output_len = strlen(*output);
            (*state).step += 1;
            return GSASL_OK as libc::c_int
        }
        _ => { }
    }
    return res;
}
/* scram.h --- Prototypes for SCRAM mechanism
 * Copyright (C) 2009-2021 Simon Josefsson
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
pub unsafe fn _gsasl_scram_server_finish(mech_data: Option<NonNull<()>>)
{
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);

    let mut state: *mut scram_server_state =
        mech_data as *mut scram_server_state;
    if state.is_null() { return }
    rpl_free((*state).cbind as *mut libc::c_void);
    rpl_free((*state).gs2header as *mut libc::c_void);
    rpl_free((*state).cfmb_str as *mut libc::c_void);
    rpl_free((*state).sf_str as *mut libc::c_void);
    rpl_free((*state).snonce as *mut libc::c_void);
    rpl_free((*state).clientproof as *mut libc::c_void);
    rpl_free((*state).authmessage as *mut libc::c_void);
    rpl_free((*state).cbtlsunique as *mut libc::c_void);
    scram_free_client_first(&mut (*state).cf);
    scram_free_server_first(&mut (*state).sf);
    scram_free_client_final(&mut (*state).cl);
    scram_free_server_final(&mut (*state).sl);
    rpl_free(state as *mut libc::c_void);
}
