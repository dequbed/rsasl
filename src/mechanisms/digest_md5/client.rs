use std::ffi::CString;
use std::ptr::NonNull;
use ::libc;
use libc::{calloc, size_t, strcmp, strdup, strlen};
use crate::gsasl::base64::gsasl_base64_to;
use crate::gsasl::callback::gsasl_callback;
use crate::gsasl::consts::{GSASL_AUTHENTICATION_ERROR, GSASL_CRYPTO_ERROR, GSASL_INTEGRITY_ERROR, GSASL_MALLOC_ERROR, GSASL_MECHANISM_CALLED_TOO_MANY_TIMES, GSASL_MECHANISM_PARSE_ERROR, GSASL_NEEDS_MORE, GSASL_NO_AUTHID, GSASL_NO_HOSTNAME, GSASL_NO_PASSWORD, GSASL_NO_SERVICE, GSASL_OK, GSASL_QOPS, GSASL_REALM};
use crate::gsasl::crypto::gsasl_nonce;
use crate::mechanisms::digest_md5::digesthmac::digest_md5_hmac;
use crate::mechanisms::digest_md5::free::{digest_md5_free_challenge, digest_md5_free_finish, digest_md5_free_response};
use crate::mechanisms::digest_md5::nonascii::utf8tolatin1ifpossible;
use crate::mechanisms::digest_md5::parser::{digest_md5_challenge, digest_md5_finish, digest_md5_parse_challenge, digest_md5_parse_finish, digest_md5_response};
use crate::mechanisms::digest_md5::printer::digest_md5_print_response;
use crate::mechanisms::digest_md5::qop::{DIGEST_MD5_QOP_AUTH, DIGEST_MD5_QOP_AUTH_INT, digest_md5_qops2qopstr};
use crate::mechanisms::digest_md5::session::{digest_md5_decode, digest_md5_encode};
use crate::gsasl::gc::GC_OK;
use crate::gsasl::gl::free::rpl_free;
use crate::gsasl::gl::gc_gnulib::gc_md5;
use crate::gsasl::property::{gsasl_property_set};
use crate::property::{AuthId, AuthzId, Hostname, Password, Qop, Realm, Service};
use crate::session::SessionData;
use crate::Shared;

extern "C" {
    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char,
                _: ...) -> libc::c_int;
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _Gsasl_digest_md5_client_state {
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
/* gc.h --- Header file for implementation agnostic crypto wrapper API.
 * Copyright (C) 2002-2005, 2007-2008, 2011-2021 Free Software Foundation, Inc.
 *
 * This file is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */
pub(crate) unsafe fn _gsasl_digest_md5_client_start(_sctx: &Shared,
                                             mech_data: &mut Option<NonNull<()>>,
) -> libc::c_int
{
    let mut state: *mut _Gsasl_digest_md5_client_state =
        0 as *mut _Gsasl_digest_md5_client_state;
    let mut nonce: [libc::c_char; 16] = [0; 16];
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut rc: libc::c_int = 0;
    rc = gsasl_nonce(nonce.as_mut_ptr(), 16 as libc::c_int as size_t);
    if rc != GSASL_OK as libc::c_int { return rc }
    rc =
        gsasl_base64_to(nonce.as_mut_ptr(), 16 as libc::c_int as size_t,
                        &mut p, 0 as *mut size_t);
    if rc != GSASL_OK as libc::c_int { return rc }
    state =
        calloc(1, ::std::mem::size_of::<_Gsasl_digest_md5_client_state>())
            as *mut _Gsasl_digest_md5_client_state;
    if state.is_null() {
        rpl_free(p as *mut libc::c_void);
        return GSASL_MALLOC_ERROR as libc::c_int
    }
    (*state).response.cnonce = p;
    (*state).response.nc = 1;
    *mech_data = NonNull::new(state as *mut ());
    return GSASL_OK as libc::c_int;
}

pub unsafe fn _gsasl_digest_md5_client_step(sctx: &mut SessionData,
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

    let mut state: *mut _Gsasl_digest_md5_client_state =
        mech_data as *mut _Gsasl_digest_md5_client_state;
    let mut rc: libc::c_int = 0;
    let mut res: libc::c_int = 0;
    *output = 0 as *mut libc::c_char;
    *output_len = 0 as libc::c_int as size_t;
    if (*state).step == 0 as libc::c_int {
        (*state).step += 1;
        if input_len == 0 {
            return GSASL_NEEDS_MORE as libc::c_int
        }
    }
    match (*state).step {
        1 => {
            if digest_md5_parse_challenge(input, input_len,
                                          &mut (*state).challenge) <
                   0 as libc::c_int {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            /* FIXME: How to let application know of remaining realms?
	   One idea, add a GSASL_REALM_COUNT property, and have the
	   GSASL_REALM be that many concatenated zero terminated realm
	   strings.  Slightly hackish, though.  Another cleaner
	   approach would be to add gsasl_property_set_array and
	   gsasl_property_get_array APIs, for those properties that
	   may be used multiple times. */
            if (*state).challenge.nrealms > 0
               {
                res =
                    gsasl_property_set(sctx, GSASL_REALM,
                                       *(*state).challenge.realms.offset(0 as
                                                                             libc::c_int
                                                                             as
                                                                             isize))
            } else {
                res =
                    gsasl_property_set(sctx, GSASL_REALM,
                                       0 as *const libc::c_char)
            }
            if res != GSASL_OK as libc::c_int { return res }
            /* FIXME: cipher, maxbuf. */
            /* Create response token. */
            (*state).response.utf8 = 1 as libc::c_int;
            res =
                gsasl_property_set(sctx, GSASL_QOPS,
                                   digest_md5_qops2qopstr((*state).challenge.qops));
            if res != GSASL_OK as libc::c_int { return res }

            if let Ok(qop) = sctx.get_property_or_callback::<Qop>() {
                if qop.as_bytes() == b"qop-int\0" {
                    (*state).response.qop = DIGEST_MD5_QOP_AUTH_INT
                } else if qop.as_bytes() == b"qop-auth\0" {
                    (*state).response.qop = DIGEST_MD5_QOP_AUTH
                } else {
                    /* We don't support confidentiality or unknown
                       keywords. */
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
            } else {
                (*state).response.qop = DIGEST_MD5_QOP_AUTH
            }

            (*state).response.nonce = strdup((*state).challenge.nonce);
            if (*state).response.nonce.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            let service = if let Ok(service) = sctx.get_property_or_callback::<Service>() {
                service.clone()
            } else {
                return GSASL_NO_SERVICE as libc::c_int
            };
            let hostname = if let Ok(hostname) = sctx.get_property_or_callback::<Hostname>() {
                hostname.clone()
            } else {
                return GSASL_NO_HOSTNAME as libc::c_int
            };
            if asprintf(&mut (*state).response.digesturi as
                            *mut *mut libc::c_char,
                        b"%s/%s\x00" as *const u8 as *const libc::c_char,
                        service.as_ptr(), hostname.as_ptr()) < 0 as libc::c_int {
                return GSASL_MALLOC_ERROR as libc::c_int
            }

            let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut tmp2: *mut libc::c_char = 0 as *mut libc::c_char;

            if let Ok(authid) = sctx.get_property_or_callback::<AuthId>() {
                let cauthid = CString::new(authid.clone()).expect("Username contains NULL");
                (*state).response.username = strdup(cauthid.as_ptr());
                if (*state).response.username.is_null() {
                    return GSASL_MALLOC_ERROR as libc::c_int;
                }
            } else {
                return GSASL_NO_AUTHID as libc::c_int;
            }

            if let Ok(authzid) = sctx.get_property_or_callback::<AuthzId>() {
                let cauthid = CString::new(authzid.clone()).expect("Username contains NULL");
                (*state).response.authzid = strdup(cauthid.as_ptr());
                if (*state).response.authzid.is_null() {
                    return GSASL_MALLOC_ERROR as libc::c_int;
                }
            }

            gsasl_callback(0 as *mut Shared, sctx, GSASL_REALM);
            if let Ok(prop) = sctx.get_property::<Realm>() {
                (*state).response.realm = strdup(prop.as_ptr());
                if (*state).response.realm.is_null() {
                    return GSASL_MALLOC_ERROR as libc::c_int
                }
            }

            if let Ok(passwd) = sctx.get_property_or_callback::<Password>() {
                let cpasswd = CString::new(passwd.clone()).expect("Username contains NULL");
                tmp2 = utf8tolatin1ifpossible(cpasswd.as_ptr());
            } else {
                return GSASL_NO_PASSWORD as libc::c_int;
            }

            rc =
                asprintf(&mut tmp as *mut *mut libc::c_char,
                         b"%s:%s:%s\x00" as *const u8 as *const libc::c_char,
                         (*state).response.username,
                         if !(*state).response.realm.is_null() {
                             (*state).response.realm
                         } else {
                             b"\x00" as *const u8 as *const libc::c_char
                         }, tmp2);
            rpl_free(tmp2 as *mut libc::c_void);
            if rc < 0 as libc::c_int {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            rc =
                gc_md5(tmp as *const libc::c_void, strlen(tmp),
                       (*state).secret.as_mut_ptr() as *mut libc::c_void) as
                    libc::c_int;
            rpl_free(tmp as *mut libc::c_void);
            if rc != GC_OK as libc::c_int {
                return GSASL_CRYPTO_ERROR as libc::c_int
            }
            rc =
                digest_md5_hmac((*state).response.response.as_mut_ptr(),
                                (*state).secret.as_mut_ptr(),
                                (*state).response.nonce,
                                (*state).response.nc,
                                (*state).response.cnonce,
                                (*state).response.qop,
                                (*state).response.authzid,
                                (*state).response.digesturi, 0 as libc::c_int,
                                (*state).response.cipher,
                                (*state).kic.as_mut_ptr(),
                                (*state).kis.as_mut_ptr(),
                                (*state).kcc.as_mut_ptr(),
                                (*state).kcs.as_mut_ptr());
            if rc != 0 { return GSASL_CRYPTO_ERROR as libc::c_int }
            *output = digest_md5_print_response(&mut (*state).response);
            if (*output).is_null() {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            *output_len = strlen(*output);
            (*state).step += 1;
            res = GSASL_NEEDS_MORE as libc::c_int
        }
        2 => {
            let mut check: [libc::c_char; 33] = [0; 33];
            if digest_md5_parse_finish(input, input_len, &mut (*state).finish)
                   < 0 as libc::c_int {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            res =
                digest_md5_hmac(check.as_mut_ptr(),
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
            if !(res != GSASL_OK as libc::c_int) {
                if strcmp((*state).finish.rspauth.as_mut_ptr(),
                          check.as_mut_ptr()) == 0 as libc::c_int {
                    res = GSASL_OK as libc::c_int
                } else { res = GSASL_AUTHENTICATION_ERROR as libc::c_int }
                (*state).step += 1
            }
        }
        _ => { res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int }
    }
    return res;
}

pub unsafe fn _gsasl_digest_md5_client_finish(mech_data: Option<NonNull<()>>)
{
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);

    let mut state: *mut _Gsasl_digest_md5_client_state =
        mech_data as *mut _Gsasl_digest_md5_client_state;
    if state.is_null() { return }
    digest_md5_free_challenge(&mut (*state).challenge);
    digest_md5_free_response(&mut (*state).response);
    digest_md5_free_finish(&mut (*state).finish);
    rpl_free(state as *mut libc::c_void);
}
pub unsafe fn _gsasl_digest_md5_client_encode(mut _sctx: &mut SessionData,
                                              mut mech_data: Option<NonNull<()>>,
                                              mut input: *const libc::c_char,
                                              mut input_len: size_t,
                                              mut output: *mut *mut libc::c_char,
                                              mut output_len: *mut size_t
    ) -> libc::c_int
{
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);

    let mut state: *mut _Gsasl_digest_md5_client_state =
        mech_data as *mut _Gsasl_digest_md5_client_state;
    let mut res: libc::c_int = 0;
    res =
        digest_md5_encode(input, input_len, output, output_len,
                          (*state).response.qop, (*state).sendseqnum,
                          (*state).kic.as_mut_ptr());
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
pub unsafe fn _gsasl_digest_md5_client_decode(mut _sctx: &mut SessionData,
                                              mech_data: Option<NonNull<()>>,
                                              mut input: *const libc::c_char,
                                              mut input_len: size_t,
                                              mut output: *mut *mut libc::c_char,
                                              mut output_len: *mut size_t
    ) -> libc::c_int
{
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);

    let mut state: *mut _Gsasl_digest_md5_client_state =
        mech_data as *mut _Gsasl_digest_md5_client_state;
    let mut res: libc::c_int = 0;
    res =
        digest_md5_decode(input, input_len, output, output_len,
                          (*state).response.qop, (*state).readseqnum,
                          (*state).kis.as_mut_ptr());
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
