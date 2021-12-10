use ::libc;
use libc::size_t;
use crate::gsasl::consts::*;
use crate::gsasl::gsasl::Gsasl_session;
use crate::gsasl::property::gsasl_property_get;
use crate::gsasl::saslprep::{GSASL_ALLOW_UNASSIGNED, gsasl_saslprep};

extern "C" {
    fn malloc(_: size_t) -> *mut libc::c_void;
    /* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* A GNU-like <string.h>.

   Copyright (C) 1995-1996, 2001-2021 Free Software Foundation, Inc.

   This file is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   This file is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

    fn rpl_free(ptr: *mut libc::c_void);

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: size_t)
     -> *mut libc::c_void;

    fn strlen(_: *const libc::c_char) -> size_t;
    /* Compute hex encoded HMAC-MD5 on the CHALLENGELEN long string
   CHALLENGE, keyed with SECRET of length SECRETLEN.  Use a
   CHALLENGELEN or SECRETLEN of 0 to indicate that CHALLENGE or
   SECRET, respectively, is zero terminated.  The RESPONSE buffer must
   be allocated by the caller, and must have room for
   CRAM_MD5_DIGEST_LEN characters.*/

    fn cram_md5_digest(challenge: *const libc::c_char, challengelen: size_t,
                       secret: *const libc::c_char, secretlen: size_t,
                       response: *mut libc::c_char);
}

/* cram-md5.h --- Prototypes for CRAM-MD5 mechanism as defined in RFC 2195.
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
/* client.c --- SASL CRAM-MD5 client side functions.
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
/* Get malloc, free. */
/* Get memcpy, strlen. */
/* Get cram_md5_digest. */
pub unsafe fn _gsasl_cram_md5_client_step(mut sctx: *mut Gsasl_session,
                                                     mut _mech_data: *mut libc::c_void,
                                                     mut input: *const libc::c_char,
                                                     mut input_len: size_t,
                                                     mut output: *mut *mut libc::c_char,
                                                     mut output_len: *mut size_t
    ) -> libc::c_int
{
    let mut response: [libc::c_char; 32] = [0; 32];
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    let mut len: size_t = 0;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut authid: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut rc: libc::c_int = 0;
    if input_len == 0 {
        *output_len = 0 as libc::c_int as size_t;
        *output = 0 as *mut libc::c_char;
        return GSASL_NEEDS_MORE as libc::c_int
    }
    p = gsasl_property_get(sctx, GSASL_AUTHID);
    if p.is_null() { return GSASL_NO_AUTHID as libc::c_int }
    /* XXX Use query strings here?  Specification is unclear. */
    rc =
        gsasl_saslprep(p, GSASL_ALLOW_UNASSIGNED, &mut authid,
                       0 as *mut libc::c_int);
    if rc != GSASL_OK as libc::c_int { return rc }
    p = gsasl_property_get(sctx, GSASL_PASSWORD);
    if p.is_null() {
        rpl_free(authid as *mut libc::c_void);
        return GSASL_NO_PASSWORD as libc::c_int
    }
    /* XXX Use query strings here?  Specification is unclear. */
    rc =
        gsasl_saslprep(p, GSASL_ALLOW_UNASSIGNED, &mut tmp,
                       0 as *mut libc::c_int);
    if rc != GSASL_OK as libc::c_int {
        rpl_free(authid as *mut libc::c_void);
        return rc
    }
    cram_md5_digest(input, input_len, tmp, strlen(tmp) as size_t,
                    response.as_mut_ptr());
    rpl_free(tmp as *mut libc::c_void);
    len = strlen(authid) as size_t;
    *output_len =
        len.wrapping_add(strlen(b" \x00" as *const u8 as *const libc::c_char) as size_t)
           .wrapping_add(32);
    *output = malloc(*output_len) as *mut libc::c_char;
    if (*output).is_null() {
        rpl_free(authid as *mut libc::c_void);
        return GSASL_MALLOC_ERROR as libc::c_int
    }
    memcpy(*output as *mut libc::c_void, authid as *const libc::c_void, len);
    let fresh0 = len;
    len = len.wrapping_add(1);
    *(*output).offset(fresh0 as isize) = ' ' as i32 as libc::c_char;
    memcpy((*output).offset(len as isize) as *mut libc::c_void,
           response.as_mut_ptr() as *const libc::c_void,
           32);
    rpl_free(authid as *mut libc::c_void);
    return GSASL_OK as libc::c_int;
}
