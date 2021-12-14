use std::ptr::NonNull;
use ::libc;
use libc::size_t;
use crate::consts::{AUTHID, AUTHZID, PASSWORD};
use crate::gsasl::consts::{GSASL_AUTHID, GSASL_AUTHZID, GSASL_MALLOC_ERROR, GSASL_NO_AUTHID, GSASL_NO_PASSWORD, GSASL_OK, GSASL_PASSWORD};
use crate::gsasl::gsasl::Gsasl_session;
use crate::gsasl::property::{gsasl_property_get, property_get};

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
pub unsafe fn _gsasl_plain_client_step(sctx: *mut Gsasl_session,
                                       _mech_data: Option<NonNull<()>>,
                                       _input: Option<&[u8]>,
                                       output: *mut *mut libc::c_char,
                                       output_len: *mut size_t
) -> libc::c_int
{
    let authzid = property_get::<AUTHZID>(sctx);
    let authid = property_get::<AUTHID>(sctx);
    let password = property_get::<PASSWORD>(sctx);

    let authzidlen: size_t = if let Some(authzid) = authzid {
        authzid.len()
    } else {
        0
    };

    if authid.is_none() {
        return GSASL_NO_AUTHID as libc::c_int
    }
    let authid = authid.unwrap();
    let authidlen = authid.len();

    if password.is_none() {
        return GSASL_NO_PASSWORD as libc::c_int
    }
    let password = password.unwrap();
    let passwordlen = authid.len();

    *output_len =
        authzidlen.wrapping_add(1)
            .wrapping_add(authidlen)
            .wrapping_add(1)
            .wrapping_add(passwordlen);

    let mut out = malloc(*output_len) as *mut libc::c_char;
    *output = out;

    if out.is_null() {
        return GSASL_MALLOC_ERROR as libc::c_int
    }

    if let Some(authzid) = authzid {
        memcpy(out as *mut libc::c_void,
               authzid.as_ptr() as *const libc::c_void,
               authzid.len());
        out = out.offset(authzid.len() as isize)
    }
    let fresh0 = out;
    out = out.offset(1);
    *fresh0 = '\u{0}' as i32 as libc::c_char;

    memcpy(out as *mut libc::c_void,
           authid.as_ptr() as *const libc::c_void,
           authidlen);
    out = out.offset(authidlen as isize);

    let fresh1 = out;
    out = out.offset(1);
    *fresh1 = '\u{0}' as i32 as libc::c_char;

    memcpy(out as *mut libc::c_void,
           password.as_ptr() as *const libc::c_void,
           passwordlen);
    return GSASL_OK as libc::c_int;
}
