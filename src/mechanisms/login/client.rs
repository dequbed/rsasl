use crate::gsasl::consts::{
    GSASL_AUTHID, GSASL_MALLOC_ERROR, GSASL_MECHANISM_CALLED_TOO_MANY_TIMES, GSASL_NEEDS_MORE,
    GSASL_NO_AUTHID, GSASL_NO_PASSWORD, GSASL_OK, GSASL_PASSWORD,
};
use crate::gsasl::gl::free::rpl_free;
use crate::gsasl::property::gsasl_property_get;
use ::libc;
use libc::{malloc, size_t, strdup, strlen};
use std::ptr::NonNull;

/* client.c --- Non-standard SASL mechanism LOGIN, client side.
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
/* Get strlen. */
/* Get specification. */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _Gsasl_login_client_state {
    pub step: libc::c_int,
}

pub(crate) unsafe fn _gsasl_login_client_start(
    _ctx: &crate::Shared,
    mech_data: &mut Option<NonNull<()>>,
) -> libc::c_int {
    let mut state;
    state = malloc(::std::mem::size_of::<_Gsasl_login_client_state>())
        as *mut _Gsasl_login_client_state;
    if state.is_null() {
        return GSASL_MALLOC_ERROR as libc::c_int;
    }
    (*state).step = 0 as libc::c_int;
    *mech_data = NonNull::new(state as *mut ());
    return GSASL_OK as libc::c_int;
}

pub unsafe fn _gsasl_login_client_step(
    sctx: &mut crate::session::MechanismData,
    mech_data: Option<NonNull<()>>,
    _input: Option<&[u8]>,
    output: *mut *mut libc::c_char,
    output_len: *mut size_t,
) -> libc::c_int {
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);

    let mut state: *mut _Gsasl_login_client_state = mech_data as *mut _Gsasl_login_client_state;
    let p;
    let res;
    match (*state).step {
        0 => {
            p = gsasl_property_get(sctx, GSASL_AUTHID);
            if p.is_null() {
                return GSASL_NO_AUTHID as libc::c_int;
            }
            *output = strdup(p);
            *output_len = strlen(p);
            (*state).step += 1;
            res = GSASL_NEEDS_MORE as libc::c_int
        }
        1 => {
            p = gsasl_property_get(sctx, GSASL_PASSWORD);
            if p.is_null() {
                return GSASL_NO_PASSWORD as libc::c_int;
            }
            *output = strdup(p);
            if (*output).is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int;
            }
            *output_len = strlen(*output);
            (*state).step += 1;
            res = GSASL_OK as libc::c_int
        }
        _ => res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int,
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
pub unsafe fn _gsasl_login_client_finish(mech_data: Option<NonNull<()>>) {
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);
    let state: *mut _Gsasl_login_client_state = mech_data as *mut _Gsasl_login_client_state;
    if state.is_null() {
        return;
    }
    rpl_free(state as *mut libc::c_void);
}
