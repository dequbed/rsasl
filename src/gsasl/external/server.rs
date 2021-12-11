use std::ptr::NonNull;
use ::libc;
use libc::size_t;
use crate::gsasl::callback::gsasl_callback;
use crate::gsasl::consts::{GSASL_AUTHZID, GSASL_MECHANISM_PARSE_ERROR, GSASL_NEEDS_MORE, GSASL_OK, GSASL_VALIDATE_EXTERNAL};
use crate::gsasl::gsasl::{Gsasl, Gsasl_session};
use crate::gsasl::property::{gsasl_property_set, gsasl_property_set_raw};

extern "C" {
    fn memchr(_: *const libc::c_void, _: libc::c_int, _: size_t)
     -> *mut libc::c_void;
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
/* server.c --- EXTERNAL mechanism as defined in RFC 2222, server side.
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
/* Get memchr. */
pub unsafe fn _gsasl_external_server_step(sctx: *mut Gsasl_session,
                                          _mech_data: Option<NonNull<()>>,
                                          input: Option<&[u8]>,
                                          output: *mut *mut libc::c_char,
                                          output_len: *mut size_t,
) -> libc::c_int
{
    let input_len = input.map(|i| i.len()).unwrap_or(0);
    let input: *const libc::c_char = input.map(|i| i.as_ptr().cast()).unwrap_or(std::ptr::null());

    let mut rc: libc::c_int = 0;
    *output_len = 0 as libc::c_int as size_t;
    *output = 0 as *mut libc::c_char;
    if input.is_null() { return GSASL_NEEDS_MORE as libc::c_int }
    /* Quoting rfc2222bis-09:
   * extern-resp       = *( UTF8-char-no-nul )
   * UTF8-char-no-nul  = UTF8-1-no-nul / UTF8-2 / UTF8-3 / UTF8-4
   * UTF8-1-no-nul     = %x01-7F */
    if !memchr(input as *const libc::c_void, '\u{0}' as i32,
               input_len).is_null() {
        return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
    }
    /* FIXME: Validate that input is UTF-8. */
    if input_len > 0 {
        rc = gsasl_property_set_raw(sctx, GSASL_AUTHZID, input, input_len)
    } else {
        rc = gsasl_property_set(sctx, GSASL_AUTHZID, 0 as *const libc::c_char)
    }
    if rc != GSASL_OK as libc::c_int { return rc }
    return gsasl_callback(0 as *mut Gsasl, sctx, GSASL_VALIDATE_EXTERNAL);
}
