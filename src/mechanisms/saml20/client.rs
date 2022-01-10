use std::ptr::NonNull;
use ::libc;
use libc::size_t;
use crate::gsasl::callback::gsasl_callback;
use crate::gsasl::consts::{GSASL_AUTHZID, GSASL_MALLOC_ERROR, GSASL_MECHANISM_CALLED_TOO_MANY_TIMES, GSASL_NEEDS_MORE, GSASL_NO_SAML20_IDP_IDENTIFIER, GSASL_OK, GSASL_SAML20_AUTHENTICATE_IN_BROWSER, GSASL_SAML20_IDP_IDENTIFIER, GSASL_SAML20_REDIRECT_URL};
use crate::gsasl::property::{gsasl_property_get, gsasl_property_set_raw};
use crate::session::SessionData;
use crate::Shared;

extern "C" {
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> size_t;
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

/* client.c --- SAML20 mechanism, client side.
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
/* Get specification. */
/* Get strdup, strlen. */
/* Get free. */
/* Get bool. */
/* Get _gsasl_gs2_generate_header. */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct saml20_client_state {
    pub step: libc::c_int,
}

pub(crate) unsafe fn _gsasl_saml20_client_start(_sctx: &Shared,
                                         mech_data: &mut Option<NonNull<()>>,
) -> libc::c_int
{
    let mut state: *mut saml20_client_state = 0 as *mut saml20_client_state;
    state = calloc(::std::mem::size_of::<saml20_client_state>(), 1)
        as *mut saml20_client_state;
    if state.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    *mech_data = NonNull::new(state as *mut ());
    return GSASL_OK as libc::c_int;
}

pub unsafe fn _gsasl_saml20_client_step(sctx: &mut SessionData,
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

    let mut state: *mut saml20_client_state =
        mech_data as *mut saml20_client_state;
    let mut res: libc::c_int =
        GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int;
    match (*state).step {
        0 => {
            let mut authzid: *const libc::c_char =
                gsasl_property_get(sctx, GSASL_AUTHZID);
            let mut idp: *const libc::c_char =
                gsasl_property_get(sctx, GSASL_SAML20_IDP_IDENTIFIER);
            if idp.is_null() || *idp == 0 {
                return GSASL_NO_SAML20_IDP_IDENTIFIER as libc::c_int
            }
            res =
                _gsasl_gs2_generate_header(0 as libc::c_int != 0,
                                           'n' as i32 as libc::c_char,
                                           0 as *const libc::c_char, authzid,
                                           strlen(idp), idp, output,
                                           output_len);
            if res != GSASL_OK as libc::c_int { return res }
            res = GSASL_NEEDS_MORE as libc::c_int;
            (*state).step += 1
        }
        1 => {
            res =
                gsasl_property_set_raw(sctx, GSASL_SAML20_REDIRECT_URL, input,
                                       input_len);
            if res != GSASL_OK as libc::c_int { return res }
            res =
                gsasl_callback(0 as *mut Shared, sctx,
                               GSASL_SAML20_AUTHENTICATE_IN_BROWSER);
            if res != GSASL_OK as libc::c_int { return res }
            *output_len = 1 as libc::c_int as size_t;
            *output = strdup(b"=\x00" as *const u8 as *const libc::c_char);
            if (*output).is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            res = GSASL_OK as libc::c_int;
            (*state).step += 1
        }
        _ => { }
    }
    return res;
}

/* saml20.h --- Prototypes for SAML20.
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
pub unsafe fn _gsasl_saml20_client_finish(mech_data: Option<NonNull<()>>)
{
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);

    let mut state: *mut saml20_client_state =
        mech_data as *mut saml20_client_state;
    if state.is_null() { return }
    rpl_free(state as *mut libc::c_void);
}
