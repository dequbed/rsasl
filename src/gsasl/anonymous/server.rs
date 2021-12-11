use std::ptr::NonNull;
use ::libc;
use libc::size_t;
use crate::gsasl::callback::gsasl_callback;
use crate::gsasl::consts::{GSASL_ANONYMOUS_TOKEN, GSASL_MECHANISM_PARSE_ERROR, GSASL_NEEDS_MORE, GSASL_OK, GSASL_VALIDATE_ANONYMOUS};
use crate::gsasl::gsasl::{Gsasl, Gsasl_session};
use crate::gsasl::property::gsasl_property_set_raw;

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
/* server.c --- ANONYMOUS mechanism as defined in RFC 2245, server side.
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
pub unsafe fn _gsasl_anonymous_server_step(sctx: *mut Gsasl_session,
                                           _mech_data: Option<NonNull<()>>,
                                           input: Option<&[u8]>,
                                           output: *mut *mut libc::c_char,
                                           output_len: *mut size_t,
) -> libc::c_int
{
    let mut rc: libc::c_int = 0;
    *output = 0 as *mut libc::c_char;
    *output_len = 0 as libc::c_int as size_t;
    if input.is_none() { return GSASL_NEEDS_MORE as libc::c_int; }
    let input = input.unwrap();
    /* token       = 1*255TCHAR
     The <token> production is restricted to 255 UTF-8 encoded Unicode
     characters.   As the encoding of a characters uses a sequence of 1
     to 4 octets, a token may be long as 1020 octets. */
    if input.len() == 0 || input.len() > 1020 {
        return GSASL_MECHANISM_PARSE_ERROR as libc::c_int;
    }
    /* FIXME: Validate that input is UTF-8. */
    rc = gsasl_property_set_raw(sctx, GSASL_ANONYMOUS_TOKEN, input.as_ptr().cast(), input.len());
    if rc != GSASL_OK as libc::c_int { return rc; }
    return gsasl_callback(0 as *mut Gsasl, sctx, GSASL_VALIDATE_ANONYMOUS);
}
