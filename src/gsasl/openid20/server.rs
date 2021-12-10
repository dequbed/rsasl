use ::libc;
use libc::size_t;
use crate::gsasl::callback::gsasl_callback;
use crate::gsasl::consts::{GSASL_AUTHENTICATION_ERROR, GSASL_AUTHID, GSASL_AUTHZID, GSASL_MALLOC_ERROR, GSASL_MECHANISM_CALLED_TOO_MANY_TIMES, GSASL_MECHANISM_PARSE_ERROR, GSASL_NEEDS_MORE, GSASL_NO_OPENID20_REDIRECT_URL, GSASL_OK, GSASL_OPENID20_OUTCOME_DATA, GSASL_OPENID20_REDIRECT_URL, GSASL_VALIDATE_OPENID20};
use crate::gsasl::gsasl::{Gsasl, Gsasl_session};
use crate::gsasl::property::{gsasl_property_get, gsasl_property_set, gsasl_property_set_raw};

extern "C" {
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: size_t)
     -> *mut libc::c_void;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn rpl_free(_: *mut libc::c_void);
    fn strlen(_: *const libc::c_char) -> size_t;
    fn malloc(_: size_t) -> *mut libc::c_void;
    fn calloc(_: size_t, _: size_t) -> *mut libc::c_void;
    /* mechtools.h --- Helper functions available for use by any mechanism.
 * Copyright (C) 2010-2021 Simon Josefsson
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
    /* Get bool. */
    fn _gsasl_parse_gs2_header(data: *const libc::c_char, len: size_t,
                               authzid: *mut *mut libc::c_char,
                               headerlen: *mut size_t) -> libc::c_int;
}
/* Get specification. */
/* Get strdup, strlen. */
/* Get calloc, free. */
/* Get _gsasl_parse_gs2_header. */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct openid20_server_state {
    pub step: libc::c_int,
    pub allow_error_step: libc::c_int,
}
pub unsafe fn _gsasl_openid20_server_start(mut _sctx:
                                                          *mut Gsasl_session,
                                                      mut mech_data:
                                                          *mut *mut libc::c_void)
 -> libc::c_int {
    let mut state: *mut openid20_server_state =
        0 as *mut openid20_server_state;
    state =
        calloc(::std::mem::size_of::<openid20_server_state>(), 1) as
            *mut openid20_server_state;
    if state.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    *mech_data = state as *mut libc::c_void;
    return GSASL_OK as libc::c_int;
}
pub unsafe fn _gsasl_openid20_server_step(mut sctx:
                                                         *mut Gsasl_session,
                                                     mut mech_data:
                                                         *mut libc::c_void,
                                                     mut input:
                                                         Option<&[u8]>,
                                                     mut output:
                                                         *mut *mut libc::c_char,
                                                     mut output_len:
                                                         *mut size_t)
 -> libc::c_int {
    let mut input_len = input.map(|i| i.len()).unwrap_or(0);
    let mut input: *const libc::c_char =
        input.map(|i| i.as_ptr().cast()).unwrap_or(std::ptr::null());

    let mut state: *mut openid20_server_state =
        mech_data as *mut openid20_server_state;
    let mut res: libc::c_int =
        GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int;
    *output_len = 0 as libc::c_int as size_t;
    *output = 0 as *mut libc::c_char;
    match (*state).step {
        0 => {
            let mut p: *const libc::c_char = 0 as *const libc::c_char;
            let mut authzid: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut headerlen: size_t = 0;
            if input_len == 0 {
                return GSASL_NEEDS_MORE as libc::c_int
            }
            res =
                _gsasl_parse_gs2_header(input, input_len, &mut authzid,
                                        &mut headerlen);
            if res != GSASL_OK as libc::c_int { return res }
            if !authzid.is_null() {
                res = gsasl_property_set(sctx, GSASL_AUTHZID, authzid);
                rpl_free(authzid as *mut libc::c_void);
                if res != GSASL_OK as libc::c_int { return res }
            }
            input = input.offset(headerlen as isize);
            input_len = input_len.wrapping_sub(headerlen);
            res =
                gsasl_property_set_raw(sctx, GSASL_AUTHID, input, input_len);
            if res != GSASL_OK as libc::c_int { return res }
            p = gsasl_property_get(sctx, GSASL_OPENID20_REDIRECT_URL);
            if p.is_null() || *p == 0 {
                return GSASL_NO_OPENID20_REDIRECT_URL as libc::c_int
            }
            *output_len = strlen(p);
            *output = malloc(*output_len) as *mut libc::c_char;
            if (*output).is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            memcpy(*output as *mut libc::c_void, p as *const libc::c_void,
                   *output_len);
            res = GSASL_NEEDS_MORE as libc::c_int;
            (*state).step += 1
        }
        1 => {
            let mut outcome_data: *const libc::c_char =
                0 as *const libc::c_char;
            if !(input_len == 1 && *input as libc::c_int == '=' as i32) {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            res =
                gsasl_callback(0 as *mut Gsasl, sctx,
                               GSASL_VALIDATE_OPENID20);
            if res != GSASL_OK as libc::c_int {
                *output =
                    strdup(b"openid.error=fail\x00" as *const u8 as
                               *const libc::c_char);
                if (*output).is_null() {
                    return GSASL_MALLOC_ERROR as libc::c_int
                }
                *output_len = strlen(*output);
                /* [RFC4422] Section 3.6 explicitly prohibits additional
	       information in an unsuccessful authentication outcome.
	       Therefore, the openid.error and openid.error_code are
	       to be sent as an additional challenge in the event of
	       an unsuccessful outcome.  In this case, as the protocol
	       is lock step, the client will follow with an additional
	       exchange containing "=", after which the server will
	       respond with an application-level outcome. */
                (*state).allow_error_step = 1 as libc::c_int;
                (*state).step += 1;
                return GSASL_NEEDS_MORE as libc::c_int
            }
            outcome_data =
                gsasl_property_get(sctx, GSASL_OPENID20_OUTCOME_DATA);
            if !outcome_data.is_null() {
                *output = strdup(outcome_data);
                if (*output).is_null() {
                    return GSASL_MALLOC_ERROR as libc::c_int
                }
                *output_len = strlen(*output) as usize
            } else {
                *output = 0 as *mut libc::c_char;
                *output_len = 0 as libc::c_int as size_t
            }
            res = GSASL_OK as libc::c_int;
            (*state).step += 1
        }
        2 => {
            /* We only get here when the previous step signalled an error
	   to the client.  */
            if (*state).allow_error_step == 0 {
                return GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int
            }
            if !(input_len == 1 && *input as libc::c_int == '=' as i32) {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            res = GSASL_AUTHENTICATION_ERROR as libc::c_int;
            (*state).step += 1
        }
        _ => { }
    }
    return res;
}
/* openid20.h --- Prototypes for OPENID20.
 * Copyright (C) 2011-2021 Simon Josefsson
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
pub unsafe fn _gsasl_openid20_server_finish(mut _sctx:
                                                           *mut Gsasl_session,
                                                       mut mech_data:
                                                           *mut libc::c_void) {
    let mut state: *mut openid20_server_state =
        mech_data as *mut openid20_server_state;
    if state.is_null() { return }
    rpl_free(state as *mut libc::c_void);
}
