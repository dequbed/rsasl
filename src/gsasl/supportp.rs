use ::libc;
use libc::size_t;
use crate::gsasl::gsasl::{Gsasl, Gsasl_mechanism};

extern "C" {
    #[no_mangle]
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
}

/* supportp.c --- Tell if a specific mechanism is supported.
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
 * License License along with GNU SASL Library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */
unsafe extern "C" fn _gsasl_support_p(mut mechs: *mut Gsasl_mechanism,
                                      mut n_mechs: size_t,
                                      mut name: *const libc::c_char)
 -> libc::c_int {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < n_mechs {
        if !name.is_null() &&
               strcmp(name, (*mechs.offset(i as isize)).name) ==
                   0 as libc::c_int {
            return 1 as libc::c_int
        }
        i = i.wrapping_add(1)
    }
    return 0 as libc::c_int;
}
/* *
 * gsasl_client_support_p:
 * @ctx: libgsasl handle.
 * @name: name of SASL mechanism.
 *
 * Decide whether there is client-side support for a specified
 * mechanism.
 *
 * Return value: Returns 1 if the libgsasl client supports the named
 * mechanism, otherwise 0.
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_client_support_p(mut ctx: *mut Gsasl,
                                                mut name: *const libc::c_char)
 -> libc::c_int {
    return _gsasl_support_p((*ctx).client_mechs, (*ctx).n_client_mechs, name);
}

/* Library entry and exit points: version.c, init.c, done.c */
/* Callback handling: callback.c */
/* Property handling: property.c */
/* Mechanism handling: listmech.c, supportp.c, suggest.c */
/* *
 * gsasl_server_support_p:
 * @ctx: libgsasl handle.
 * @name: name of SASL mechanism.
 *
 * Decide whether there is server-side support for a specified
 * mechanism.
 *
 * Return value: Returns 1 if the libgsasl server supports the named
 * mechanism, otherwise 0.
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_server_support_p(mut ctx: *mut Gsasl,
                                                mut name: *const libc::c_char)
 -> libc::c_int {
    return _gsasl_support_p((*ctx).server_mechs, (*ctx).n_server_mechs, name);
}