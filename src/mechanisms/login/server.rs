use std::ptr::NonNull;
use ::libc;
use libc::size_t;
use crate::gsasl::callback::gsasl_callback;
use crate::gsasl::consts::{GSASL_AUTHENTICATION_ERROR, GSASL_AUTHID, GSASL_MALLOC_ERROR, GSASL_MECHANISM_CALLED_TOO_MANY_TIMES, GSASL_MECHANISM_PARSE_ERROR, GSASL_NEEDS_MORE, GSASL_NO_CALLBACK, GSASL_OK, GSASL_PASSWORD, GSASL_VALIDATE_SIMPLE};
use crate::gsasl::property::{gsasl_property_get, gsasl_property_set};
use crate::{Shared, SessionData};

extern "C" {
    /* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* A GNU-like <string.h>.

   Copyright (C) 1995-1996, 2001-2021 Free Software Foundation, Inc.

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
    fn rpl_free(ptr: *mut libc::c_void);
    fn calloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strndup(_: *const libc::c_char, _: size_t) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> size_t;
}

/* server.c --- Non-standard SASL mechanism LOGIN, server side.
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
/* Get malloc, free. */
/* Get strdup, strlen. */
/* Get specification. */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _Gsasl_login_server_state {
    pub step: libc::c_int,
    pub username: *mut libc::c_char,
    pub password: *mut libc::c_char,
}

pub unsafe fn _gsasl_login_server_start(_sctx: &Shared,
                                        mech_data: &mut Option<NonNull<()>>,
)
    -> libc::c_int {
    let mut state: *mut _Gsasl_login_server_state =
        0 as *mut _Gsasl_login_server_state;
    state = calloc(1, ::std::mem::size_of::<_Gsasl_login_server_state>())
            as *mut _Gsasl_login_server_state;
    if state.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    *mech_data = NonNull::new(state as *mut ());
    return GSASL_OK as libc::c_int;
}

pub unsafe fn _gsasl_login_server_step(sctx: &mut SessionData,
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

    let mut state: *mut _Gsasl_login_server_state =
        mech_data as *mut _Gsasl_login_server_state;
    let mut res: libc::c_int = 0;
    match (*state).step {
        0 => {
            *output = strdup(b"User Name\x00" as *const u8 as *const libc::c_char);
            if (*output).is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            *output_len = strlen(b"User Name\x00" as *const u8 as *const libc::c_char);
            (*state).step += 1;
            res = GSASL_NEEDS_MORE as libc::c_int
        }
        1 => {
            if input_len == 0 {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            (*state).username = strndup(input, input_len);
            if (*state).username.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            if input_len != strlen((*state).username) {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            *output =
                strdup(b"Password\x00" as *const u8 as *const libc::c_char);
            if (*output).is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            *output_len =
                strlen(b"Password\x00" as *const u8 as *const libc::c_char);
            (*state).step += 1;
            res = GSASL_NEEDS_MORE as libc::c_int
        }
        2 => {
            if input_len == 0 {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            (*state).password = strndup(input, input_len);
            if (*state).password.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            if input_len != strlen((*state).password) {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            res = gsasl_property_set(sctx, GSASL_AUTHID, (*state).username);
            if res != GSASL_OK as libc::c_int { return res }
            res = gsasl_property_set(sctx, GSASL_PASSWORD, (*state).password);
            if res != GSASL_OK as libc::c_int { return res }
            res =
                gsasl_callback(0 as *mut Shared, sctx, GSASL_VALIDATE_SIMPLE);
            if res == GSASL_NO_CALLBACK as libc::c_int {
                let mut key: *const libc::c_char = 0 as *const libc::c_char;
                key = gsasl_property_get(sctx, GSASL_PASSWORD);
                if !key.is_null() && strlen((*state).password) == strlen(key)
                       && strcmp((*state).password, key) == 0 as libc::c_int {
                    res = GSASL_OK as libc::c_int
                } else { res = GSASL_AUTHENTICATION_ERROR as libc::c_int }
            }
            *output_len = 0;
            *output = 0 as *mut libc::c_char;
            (*state).step += 1
        }
        _ => { res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int }
    }
    return res;
}
/* login.h --- Prototypes for non-standard SASL mechanism LOGIN.
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
pub unsafe fn _gsasl_login_server_finish(mech_data: Option<NonNull<()>>)
{
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);

    let mut state: *mut _Gsasl_login_server_state =
        mech_data as *mut _Gsasl_login_server_state;
    if state.is_null() { return }
    rpl_free((*state).username as *mut libc::c_void);
    rpl_free((*state).password as *mut libc::c_void);
    rpl_free(state as *mut libc::c_void);
}
