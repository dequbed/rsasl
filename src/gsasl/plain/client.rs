use ::libc;
use libc::size_t;
use crate::gsasl::consts::{GSASL_AUTHID, GSASL_AUTHZID, GSASL_MALLOC_ERROR, GSASL_NO_AUTHID, GSASL_NO_PASSWORD, GSASL_OK, GSASL_PASSWORD};
use crate::gsasl::gsasl::Gsasl_session;
use crate::gsasl::property::gsasl_property_get;

extern "C" {
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: size_t)
     -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> size_t;
    fn malloc(_: size_t) -> *mut libc::c_void;
}

/* plain.h --- Prototypes for SASL mechanism PLAIN as defined in RFC 2595.
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
/* client.c --- SASL mechanism PLAIN as defined in RFC 2595, client side.
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
/* Get specification. */
/* Get memcpy, strdup, strlen. */
/* Get malloc, free. */
#[no_mangle]
pub unsafe extern "C" fn _gsasl_plain_client_step(mut sctx: *mut Gsasl_session,
                                                  mut _mech_data: *mut libc::c_void,
                                                  mut _input: *const libc::c_char,
                                                  mut _input_len: size_t,
                                                  mut output: *mut *mut libc::c_char,
                                                  mut output_len: *mut size_t)
 -> libc::c_int {
    let mut authzid: *const libc::c_char =
        gsasl_property_get(sctx, GSASL_AUTHZID);
    let mut authid: *const libc::c_char =
        gsasl_property_get(sctx, GSASL_AUTHID);
    let mut password: *const libc::c_char =
        gsasl_property_get(sctx, GSASL_PASSWORD);
    let mut authzidlen: size_t = 0;
    let mut authidlen: size_t = 0;
    let mut passwordlen: size_t = 0;
    let mut out: *mut libc::c_char = 0 as *mut libc::c_char;
    if !authzid.is_null() { authzidlen = strlen(authzid) }
    if !authid.is_null() {
        authidlen = strlen(authid)
    } else { return GSASL_NO_AUTHID as libc::c_int }
    if !password.is_null() {
        passwordlen = strlen(password)
    } else { return GSASL_NO_PASSWORD as libc::c_int }
    *output_len =
        authzidlen.wrapping_add(1)
            .wrapping_add(authidlen)
            .wrapping_add(1)
            .wrapping_add(passwordlen);

    out = malloc(*output_len) as *mut libc::c_char;
    *output = out;
    if out.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    if !authzid.is_null() {
        memcpy(out as *mut libc::c_void, authzid as *const libc::c_void,
               authzidlen);
        out = out.offset(authzidlen as isize)
    }
    let fresh0 = out;
    out = out.offset(1);
    *fresh0 = '\u{0}' as i32 as libc::c_char;
    memcpy(out as *mut libc::c_void, authid as *const libc::c_void,
           authidlen);
    out = out.offset(authidlen as isize);
    let fresh1 = out;
    out = out.offset(1);
    *fresh1 = '\u{0}' as i32 as libc::c_char;
    memcpy(out as *mut libc::c_void, password as *const libc::c_void,
           passwordlen);
    return GSASL_OK as libc::c_int;
}
