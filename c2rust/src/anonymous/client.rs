use ::libc;
use libc::size_t;
use crate::consts::{GSASL_ANONYMOUS_TOKEN, GSASL_MALLOC_ERROR, GSASL_NO_ANONYMOUS_TOKEN, GSASL_OK, Gsasl_property};
use crate::gsasl::Gsasl_session;
use crate::property::gsasl_property_get;

extern "C" {
    #[no_mangle]
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> size_t;
}

/* anonymous.h --- Prototypes for ANONYMOUS mechanism as defined in RFC 2245.
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
/* client.c --- ANONYMOUS mechanism as defined in RFC 2245, client side.
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
/* Get strdup, strlen. */
#[no_mangle]
pub unsafe extern "C" fn _gsasl_anonymous_client_step(mut sctx: *mut Gsasl_session,
                                                      mut mech_data: *mut libc::c_void,
                                                      mut input: *const libc::c_char,
                                                      mut input_len: size_t,
                                                      mut output: *mut *mut libc::c_char,
                                                      mut output_len: *mut size_t)
 -> libc::c_int {
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    p = gsasl_property_get(sctx, GSASL_ANONYMOUS_TOKEN);
    if p.is_null() { return GSASL_NO_ANONYMOUS_TOKEN as libc::c_int }
    *output = strdup(p);
    if (*output).is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    *output_len = strlen(p);
    return GSASL_OK as libc::c_int;
}
