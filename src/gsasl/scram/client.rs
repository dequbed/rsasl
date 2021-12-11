use std::ptr::NonNull;
use ::libc;
use libc::size_t;
use crate::gsasl::base64::{gsasl_base64_from, gsasl_base64_to};
use crate::gsasl::consts::{GSASL_AUTHENTICATION_ERROR, GSASL_AUTHID, GSASL_AUTHZID, GSASL_CB_TLS_UNIQUE, GSASL_MALLOC_ERROR, GSASL_MECHANISM_CALLED_TOO_MANY_TIMES, GSASL_MECHANISM_PARSE_ERROR, GSASL_NEEDS_MORE, GSASL_NO_AUTHID, GSASL_NO_CB_TLS_UNIQUE, GSASL_NO_PASSWORD, GSASL_OK, GSASL_PASSWORD, GSASL_SCRAM_ITER, GSASL_SCRAM_SALT, GSASL_SCRAM_SALTED_PASSWORD};
use crate::gsasl::crypto::{gsasl_hash_length, gsasl_nonce, gsasl_scram_secrets_from_password, gsasl_scram_secrets_from_salted_password};
use crate::gsasl::free::gsasl_free;
use crate::gsasl::gsasl::Gsasl_session;
use crate::gsasl::mechtools::{_gsasl_hex_decode, _gsasl_hex_p, _gsasl_hmac, Gsasl_hash, GSASL_HASH_SHA1, GSASL_HASH_SHA256};
use crate::gsasl::property::{gsasl_property_get, gsasl_property_set};
use crate::gsasl::saslprep::{GSASL_ALLOW_UNASSIGNED, gsasl_saslprep};
use crate::gsasl::scram::parser::{scram_parse_server_final, scram_parse_server_first};
use crate::gsasl::scram::printer::{scram_print_client_final, scram_print_client_first};
use crate::gsasl::scram::server::{scram_server_final, scram_server_first};
use crate::gsasl::scram::tokens::{scram_free_client_final, scram_free_client_first, scram_free_server_final, scram_free_server_first};
use crate::gsasl::scram::tools::set_saltedpassword;

extern "C" {
    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char,
                _: ...) -> libc::c_int;
    fn malloc(_: size_t) -> *mut libc::c_void;
    fn calloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn rpl_free(ptr: *mut libc::c_void);
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: size_t) -> *mut libc::c_void;
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: size_t) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> size_t;
    fn memxor(dest: *mut libc::c_void, src: *const libc::c_void, n: size_t)
     -> *mut libc::c_void;
}

/* Crypto functions: crypto.c */
/* *
   * Gsasl_hash:
   * @GSASL_HASH_SHA1: Hash function SHA-1.
   * @GSASL_HASH_SHA256: Hash function SHA-256.
   *
   * Hash functions.  You may use gsasl_hash_length() to get the
   * output size of a hash function.
   *
   * Currently only used as parameter to
   * gsasl_scram_secrets_from_salted_password() and
   * gsasl_scram_secrets_from_password() to specify for which SCRAM
   * mechanism to prepare secrets for.
   *
   * Since: 1.10
   */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_client_state {
    pub plus: bool,
    pub hash: Gsasl_hash,
    pub step: libc::c_int,
    pub cfmb: *mut libc::c_char,
    pub serversignature: *mut libc::c_char,
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
pub struct scram_client_final {
    pub cbind: *mut libc::c_char,
    pub nonce: *mut libc::c_char,
    pub proof: *mut libc::c_char,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_client_first {
    pub cbflag: libc::c_char,
    pub cbname: *mut libc::c_char,
    pub authzid: *mut libc::c_char,
    pub username: *mut libc::c_char,
    pub client_nonce: *mut libc::c_char,
}
unsafe fn scram_start(mut _sctx: *mut Gsasl_session,
                                 mut mech_data: *mut *mut libc::c_void,
                                 mut plus: bool, mut hash: Gsasl_hash)
 -> libc::c_int {
    let mut state: *mut scram_client_state = 0 as *mut scram_client_state;
    let mut buf: [libc::c_char; 18] = [0; 18];
    let mut rc: libc::c_int = 0;
    state = calloc(::std::mem::size_of::<scram_client_state>(), 1) as *mut scram_client_state;
    if state.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    (*state).plus = plus;
    (*state).hash = hash;
    rc = gsasl_nonce(buf.as_mut_ptr(), 18 as libc::c_int as size_t);
    if rc != GSASL_OK as libc::c_int {
        rpl_free(state as *mut libc::c_void);
        return rc
    }
    rc = gsasl_base64_to(buf.as_mut_ptr(), 18,
                         &mut (*state).cf.client_nonce, 0 as *mut size_t);
    if rc != GSASL_OK as libc::c_int {
        rpl_free(state as *mut libc::c_void);
        return rc
    }
    *mech_data = state as *mut libc::c_void;
    return GSASL_OK as libc::c_int;
}

pub unsafe fn _gsasl_scram_sha1_client_start(sctx: &mut Gsasl_session,
                                             mech_data: &mut Option<NonNull<()>>,
) -> libc::c_int
{
    let mut ptr = mech_data
        .map(|ptr| ptr.as_ptr().cast())
        .unwrap_or_else(std::ptr::null_mut);

    let ret =  scram_start(sctx,
                           &mut ptr,
                           0 as libc::c_int != 0,
                           GSASL_HASH_SHA1);

    *mech_data = NonNull::new(ptr.cast());

    return ret;
}

pub unsafe fn _gsasl_scram_sha1_plus_client_start(sctx: &mut Gsasl_session,
                                                  mech_data: &mut Option<NonNull<()>>
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

pub unsafe fn _gsasl_scram_sha256_client_start(sctx: &mut Gsasl_session,
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
    assert!(!ptr.is_null());
    *mech_data = NonNull::new(ptr.cast());

    return ret;
}

pub unsafe fn _gsasl_scram_sha256_plus_client_start(mut sctx: &mut Gsasl_session,
                                                    mut mech_data: &mut Option<NonNull<()>>,
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

pub unsafe fn _gsasl_scram_client_step(sctx: *mut Gsasl_session,
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

    let mut state: *mut scram_client_state =
        mech_data as *mut scram_client_state;
    let mut res: libc::c_int =
        GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int;
    let mut rc: libc::c_int = 0;
    *output = 0 as *mut libc::c_char;
    *output_len = 0 as libc::c_int as size_t;
    match (*state).step {
        0 => {
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
            if (*state).plus {
                (*state).cf.cbflag = 'p' as i32 as libc::c_char;
                (*state).cf.cbname =
                    strdup(b"tls-unique\x00" as *const u8 as
                               *const libc::c_char)
            } else if (*state).cbtlsuniquelen > 0 {
                (*state).cf.cbflag = 'y' as i32 as libc::c_char
            } else { (*state).cf.cbflag = 'n' as i32 as libc::c_char }
            p = gsasl_property_get(sctx, GSASL_AUTHID);
            if p.is_null() { return GSASL_NO_AUTHID as libc::c_int }
            rc = gsasl_saslprep(p, GSASL_ALLOW_UNASSIGNED,
                               &mut (*state).cf.username,
                               0 as *mut libc::c_int);
            if rc != GSASL_OK as libc::c_int { return rc }
            p = gsasl_property_get(sctx, GSASL_AUTHZID);
            if !p.is_null() { (*state).cf.authzid = strdup(p) }
            rc = scram_print_client_first(&mut (*state).cf, output);
            if rc == -(2 as libc::c_int) {
                return GSASL_MALLOC_ERROR as libc::c_int
            } else {
                if rc != 0 as libc::c_int {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
            }
            *output_len = strlen(*output);
            /* Point p to client-first-message-bare. */
            p = strchr(*output, ',' as i32);
            if p.is_null() {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            p = p.offset(1);
            p = strchr(p, ',' as i32);
            if p.is_null() {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            p = p.offset(1);
            /* Save "client-first-message-bare" for the next step. */
            (*state).cfmb = strdup(p);
            if (*state).cfmb.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            /* Prepare B64("cbind-input") for the next step. */
            if (*state).cf.cbflag as libc::c_int == 'p' as i32 {
                let mut len: size_t = (p.offset_from(*output))
                    .wrapping_add((*state).cbtlsuniquelen as isize) as usize;
                let mut cbind_input: *mut libc::c_char =
                    malloc(len) as *mut libc::c_char;
                if cbind_input.is_null() {
                    return GSASL_MALLOC_ERROR as libc::c_int
                }
                memcpy(cbind_input as *mut libc::c_void,
                       *output as *const libc::c_void,
                       p.offset_from(*output) as size_t);
                memcpy(cbind_input.offset(p.offset_from(*output)) as
                           *mut libc::c_void,
                       (*state).cbtlsunique as *const libc::c_void,
                       (*state).cbtlsuniquelen);
                rc =
                    gsasl_base64_to(cbind_input, len, &mut (*state).cl.cbind,
                                    0 as *mut size_t);
                rpl_free(cbind_input as *mut libc::c_void);
            } else {
                rc =
                    gsasl_base64_to(*output,
                                    p.offset_from(*output) as
                                        libc::c_long as size_t,
                                    &mut (*state).cl.cbind, 0 as *mut size_t)
            }
            if rc != 0 as libc::c_int { return rc }
            /* We are done. */
            (*state).step += 1;
            return GSASL_NEEDS_MORE as libc::c_int
        }
        1 => {
            if scram_parse_server_first(input, input_len, &mut (*state).sf) <
                   0 as libc::c_int {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            if strlen((*state).sf.nonce) < strlen((*state).cf.client_nonce) ||
                   memcmp((*state).cf.client_nonce as *const libc::c_void,
                          (*state).sf.nonce as *const libc::c_void,
                          strlen((*state).cf.client_nonce)) !=
                       0 as libc::c_int {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            (*state).cl.nonce = strdup((*state).sf.nonce);
            if (*state).cl.nonce.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
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
            rc = gsasl_property_set(sctx, GSASL_SCRAM_SALT, (*state).sf.salt);
            if rc != GSASL_OK as libc::c_int { return rc }
            /* Generate ClientProof. */
            let mut saltedpassword: [libc::c_char; 32] = [0; 32];
            let mut clientkey: [libc::c_char; 32] = [0; 32];
            let mut serverkey: [libc::c_char; 32] = [0; 32];
            let mut storedkey: [libc::c_char; 32] = [0; 32];
            let mut p_0: *const libc::c_char = 0 as *const libc::c_char;
            /* Get SaltedPassword. */
            p_0 = gsasl_property_get(sctx, GSASL_SCRAM_SALTED_PASSWORD);
            if !p_0.is_null()
                && strlen(p_0) == (2 as size_t).wrapping_mul(gsasl_hash_length((*state).hash))
                && _gsasl_hex_p(p_0) as libc::c_int != 0
            {
                _gsasl_hex_decode(p_0, saltedpassword.as_mut_ptr());
                rc =
                    gsasl_scram_secrets_from_salted_password((*state).hash,
                                                             saltedpassword.as_mut_ptr(),
                                                             clientkey.as_mut_ptr(),
                                                             serverkey.as_mut_ptr(),
                                                             storedkey.as_mut_ptr());
                if rc != 0 as libc::c_int { return rc }
            } else {
                p_0 = gsasl_property_get(sctx, GSASL_PASSWORD);
                if !p_0.is_null() {
                    let mut salt: *mut libc::c_char = 0 as *mut libc::c_char;
                    let mut saltlen: size_t = 0;
                    rc =
                        gsasl_base64_from((*state).sf.salt,
                                          strlen((*state).sf.salt), &mut salt,
                                          &mut saltlen);
                    if rc != 0 as libc::c_int { return rc }
                    rc =
                        gsasl_scram_secrets_from_password((*state).hash, p_0,
                                                          (*state).sf.iter as
                                                              libc::c_uint,
                                                          salt, saltlen,
                                                          saltedpassword.as_mut_ptr(),
                                                          clientkey.as_mut_ptr(),
                                                          serverkey.as_mut_ptr(),
                                                          storedkey.as_mut_ptr());
                    if rc != 0 as libc::c_int { return rc }
                    rc =
                        set_saltedpassword(sctx, (*state).hash,
                                           saltedpassword.as_mut_ptr());
                    if rc != GSASL_OK as libc::c_int { return rc }
                    gsasl_free(salt as *mut libc::c_void);
                } else { return GSASL_NO_PASSWORD as libc::c_int }
            }
            /* Get client-final-message-without-proof. */
            let mut cfmwp: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut n_0: libc::c_int = 0;
            (*state).cl.proof =
                strdup(b"p\x00" as *const u8 as *const libc::c_char);
            rc = scram_print_client_final(&mut (*state).cl, &mut cfmwp);
            if rc != 0 as libc::c_int {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            rpl_free((*state).cl.proof as *mut libc::c_void);
            /* Compute AuthMessage */
            n_0 =
                asprintf(&mut (*state).authmessage as *mut *mut libc::c_char,
                         b"%s,%.*s,%.*s\x00" as *const u8 as
                             *const libc::c_char, (*state).cfmb,
                         input_len as libc::c_int, input,
                         strlen(cfmwp).wrapping_sub(4) as libc::c_int, cfmwp);
            rpl_free(cfmwp as *mut libc::c_void);
            if n_0 <= 0 as libc::c_int || (*state).authmessage.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            let mut clientsignature: [libc::c_char; 32] = [0; 32];
            let mut clientproof: [libc::c_char; 32] = [0; 32];
            /* ClientSignature := HMAC(StoredKey, AuthMessage) */
            rc =
                _gsasl_hmac((*state).hash, storedkey.as_mut_ptr(),
                            gsasl_hash_length((*state).hash),
                            (*state).authmessage,
                            strlen((*state).authmessage),
                            clientsignature.as_mut_ptr());
            if rc != 0 as libc::c_int { return rc }
            /* ClientProof := ClientKey XOR ClientSignature */
            memcpy(clientproof.as_mut_ptr() as *mut libc::c_void,
                   clientkey.as_mut_ptr() as *const libc::c_void,
                   gsasl_hash_length((*state).hash));
            memxor(clientproof.as_mut_ptr() as *mut libc::c_void,
                   clientsignature.as_mut_ptr() as *const libc::c_void,
                   gsasl_hash_length((*state).hash));
            rc =
                gsasl_base64_to(clientproof.as_mut_ptr(),
                                gsasl_hash_length((*state).hash),
                                &mut (*state).cl.proof, 0 as *mut size_t);
            if rc != 0 as libc::c_int { return rc }
            /* Generate ServerSignature, for comparison in next step. */
            let mut serversignature: [libc::c_char; 32] = [0; 32];
            /* ServerSignature := HMAC(ServerKey, AuthMessage) */
            rc =
                _gsasl_hmac((*state).hash, serverkey.as_mut_ptr(),
                            gsasl_hash_length((*state).hash),
                            (*state).authmessage,
                            strlen((*state).authmessage),
                            serversignature.as_mut_ptr());
            if rc != 0 as libc::c_int { return rc }
            rc =
                gsasl_base64_to(serversignature.as_mut_ptr(),
                                gsasl_hash_length((*state).hash),
                                &mut (*state).serversignature,
                                0 as *mut size_t);
            if rc != 0 as libc::c_int { return rc }
            rc = scram_print_client_final(&mut (*state).cl, output);
            if rc != 0 as libc::c_int {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            *output_len = strlen(*output);
            (*state).step += 1;
            return GSASL_NEEDS_MORE as libc::c_int
        }
        2 => {
            if scram_parse_server_final(input, input_len, &mut (*state).sl) <
                   0 as libc::c_int {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            if strcmp((*state).sl.verifier, (*state).serversignature) !=
                   0 as libc::c_int {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            (*state).step += 1;
            return GSASL_OK as libc::c_int
        }
        _ => { }
    }
    return res;
}

pub unsafe fn _gsasl_scram_client_finish(mut _sctx: *mut Gsasl_session,
                                         mech_data: Option<NonNull<()>>)
{
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);

    let mut state: *mut scram_client_state =
        mech_data as *mut scram_client_state;
    if state.is_null() { return }
    rpl_free((*state).cfmb as *mut libc::c_void);
    rpl_free((*state).serversignature as *mut libc::c_void);
    rpl_free((*state).authmessage as *mut libc::c_void);
    rpl_free((*state).cbtlsunique as *mut libc::c_void);
    scram_free_client_first(&mut (*state).cf);
    scram_free_server_first(&mut (*state).sf);
    scram_free_client_final(&mut (*state).cl);
    scram_free_server_final(&mut (*state).sl);
    rpl_free(state as *mut libc::c_void);
}
