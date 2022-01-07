use std::ptr::NonNull;
use ::libc;
use libc::size_t;
use crate::consts::AnonymousToken;
use crate::gsasl::consts::{GSASL_MALLOC_ERROR, GSASL_NO_ANONYMOUS_TOKEN,
                           GSASL_OK};
use crate::SessionData;

extern "C" {
    fn strndup(_: *const libc::c_char, _: size_t) -> *mut libc::c_char;
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
pub unsafe fn _gsasl_anonymous_client_step(sctx: &mut SessionData,
                                           _mech_data: Option<NonNull<()>>,
                                           _input: Option<&[u8]>,
                                           output: *mut *mut libc::c_char,
                                           output_len: *mut size_t
) -> libc::c_int
{
    if let Some(token) = sctx.get_property_or_callback::<AnonymousToken>() {
        *output = strndup(token.as_ptr() as *const libc::c_char, token.len());

        if (*output).is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
        *output_len = token.len();

        GSASL_OK as libc::c_int
    } else {

        GSASL_NO_ANONYMOUS_TOKEN as libc::c_int
    }
}
