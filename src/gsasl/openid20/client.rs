use std::ptr::NonNull;
use ::libc;
use libc::size_t;
use crate::gsasl::callback::gsasl_callback;
use crate::gsasl::consts::{GSASL_AUTHID, GSASL_AUTHZID, GSASL_MALLOC_ERROR, GSASL_MECHANISM_CALLED_TOO_MANY_TIMES, GSASL_NEEDS_MORE, GSASL_NO_AUTHID, GSASL_OK, GSASL_OPENID20_AUTHENTICATE_IN_BROWSER, GSASL_OPENID20_OUTCOME_DATA, GSASL_OPENID20_REDIRECT_URL};
use crate::gsasl::gsasl::{Gsasl, Gsasl_session};
use crate::gsasl::property::{gsasl_property_get, gsasl_property_set_raw};

extern "C" {
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char,
               _: size_t) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> size_t;
    /* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* A GNU-like <stdlib.h>.

   Copyright (C) 1995, 2001-2004, 2006-2021 Free Software Foundation, Inc.

   This file is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   This file is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */
    fn rpl_free(_: *mut libc::c_void);
    fn calloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn _gsasl_gs2_generate_header(nonstd: bool, cbflag: libc::c_char,
                                  cbname: *const libc::c_char,
                                  authzid: *const libc::c_char,
                                  extralen: size_t,
                                  extra: *const libc::c_char,
                                  gs2h: *mut *mut libc::c_char,
                                  gs2hlen: *mut size_t) -> libc::c_int;
}

/* client.c --- OPENID20 mechanism, client side.
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
/* Get specification. */
/* Get strdup, strlen. */
/* Get calloc, free. */
/* Get bool. */
/* Get _gsasl_gs2_generate_header. */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct openid20_client_state {
    pub step: libc::c_int,
}

pub unsafe fn _gsasl_openid20_client_start(_sctx: &mut Gsasl_session,
                                           mech_data: &mut Option<NonNull<()>>,
) -> libc::c_int
{
    let mut state: *mut openid20_client_state =
        0 as *mut openid20_client_state;
    state = calloc(::std::mem::size_of::<openid20_client_state>(), 1) as
            *mut openid20_client_state;
    if state.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    *mech_data = NonNull::new(state as *mut ());
    return GSASL_OK as libc::c_int;
}

pub unsafe fn _gsasl_openid20_client_step(sctx: *mut Gsasl_session,
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

    let mut state: *mut openid20_client_state = mech_data as *mut openid20_client_state;
    let mut res: libc::c_int = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int;
    match (*state).step {
        0 => {
            let mut authzid: *const libc::c_char =
                gsasl_property_get(sctx, GSASL_AUTHZID);
            let mut authid: *const libc::c_char =
                gsasl_property_get(sctx, GSASL_AUTHID);
            if authid.is_null() || *authid == 0 {
                return GSASL_NO_AUTHID as libc::c_int
            }
            res =
                _gsasl_gs2_generate_header(0 as libc::c_int != 0,
                                           'n' as i32 as libc::c_char,
                                           0 as *const libc::c_char, authzid,
                                           strlen(authid), authid, output,
                                           output_len);
            if res != GSASL_OK as libc::c_int { return res }
            res = GSASL_NEEDS_MORE as libc::c_int;
            (*state).step += 1
        }
        1 => {
            res =
                gsasl_property_set_raw(sctx, GSASL_OPENID20_REDIRECT_URL,
                                       input, input_len);
            if res != GSASL_OK as libc::c_int { return res }
            res =
                gsasl_callback(0 as *mut Gsasl, sctx,
                               GSASL_OPENID20_AUTHENTICATE_IN_BROWSER);
            if res != GSASL_OK as libc::c_int { return res }
            *output_len = 1 as libc::c_int as size_t;
            *output = strdup(b"=\x00" as *const u8 as *const libc::c_char);
            if (*output).is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            res = GSASL_OK as libc::c_int;
            (*state).step += 1
        }
        2 => {
            /* This step is optional.  The server could have approved
         authentication already.  Alternatively, it wanted to send
         some SREGs or error data and we end up here. */
            res =
                gsasl_property_set_raw(sctx, GSASL_OPENID20_OUTCOME_DATA,
                                       input, input_len);
            if res != GSASL_OK as libc::c_int { return res }
            /* In the case of failures, the response MUST follow this
	   syntax:

	   outcome_data = "openid.error" "=" sreg_val *( "," sregp_avp )

	   [RFC4422] Section 3.6 explicitly prohibits additional information in
	   an unsuccessful authentication outcome.  Therefore, the openid.error
	   and openid.error_code are to be sent as an additional challenge in
	   the event of an unsuccessful outcome.  In this case, as the protocol
	   is lock step,  the client will follow with an additional exchange
	   containing "=", after which the server will respond with an
	   application-level outcome.
	 */
            if input_len >
                   strlen(b"openid.error=\x00" as *const u8 as
                              *const libc::c_char) &&
                   strncmp(b"openid.error=\x00" as *const u8 as
                               *const libc::c_char, input,
                           strlen(b"openid.error=\x00" as *const u8 as
                                      *const libc::c_char)) ==
                       0 as libc::c_int {
                *output_len = 1 as libc::c_int as size_t;
                *output =
                    strdup(b"=\x00" as *const u8 as *const libc::c_char);
                if (*output).is_null() {
                    return GSASL_MALLOC_ERROR as libc::c_int
                }
                res = GSASL_NEEDS_MORE as libc::c_int
            } else {
                *output_len = 0 as libc::c_int as size_t;
                *output = 0 as *mut libc::c_char;
                res = GSASL_OK as libc::c_int
            }
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
pub unsafe fn _gsasl_openid20_client_finish(mut _sctx: *mut Gsasl_session,
                                            mech_data: Option<NonNull<()>>)
{
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);

    let mut state: *mut openid20_client_state =
        mech_data as *mut openid20_client_state;
    if state.is_null() { return }
    rpl_free(state as *mut libc::c_void);
}
