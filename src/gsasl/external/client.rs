use ::libc;
use libc::size_t;
use crate::gsasl::consts::{GSASL_AUTHZID, GSASL_MALLOC_ERROR, GSASL_OK};
use crate::gsasl::gsasl::Gsasl_session;
use crate::gsasl::property::gsasl_property_get;

extern "C" {
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> size_t;
}
/* external.h --- Prototypes for EXTERNAL mechanism as defined in RFC 2222.
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
/* client.c --- EXTERNAL mechanism as defined in RFC 2222, client side.
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
pub unsafe fn _gsasl_external_client_step(mut sctx: *mut Gsasl_session,
                                                     mut _mech_data: *mut libc::c_void,
                                                     mut _input: *const libc::c_char,
                                                     mut _input_len: size_t,
                                                     mut output: *mut *mut libc::c_char,
                                                     mut output_len: *mut size_t
    ) -> libc::c_int
{
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    p = gsasl_property_get(sctx, GSASL_AUTHZID);
    if p.is_null() { p = b"\x00" as *const u8 as *const libc::c_char }
    *output = strdup(p);
    if (*output).is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    *output_len = strlen(p);
    return GSASL_OK as libc::c_int;
}
