use ::libc;
use libc::size_t;
use crate::consts::{GSASL_AUTHENTICATION_ERROR, GSASL_AUTHID, GSASL_CRYPTO_ERROR, GSASL_MALLOC_ERROR, GSASL_MECHANISM_PARSE_ERROR, GSASL_NEEDS_MORE, GSASL_NO_PASSWORD, GSASL_OK, GSASL_PASSWORD, Gsasl_property};
use crate::gsasl::Gsasl_session;
use crate::property::{gsasl_property_get, gsasl_property_set};
use crate::saslprep::{gsasl_saslprep, Gsasl_saslprep_flags};

extern "C" {
    #[no_mangle]
    fn malloc(_: size_t) -> *mut libc::c_void;
    #[no_mangle]
    fn calloc(_: size_t, _: size_t) -> *mut libc::c_void;
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
    #[no_mangle]
    fn rpl_free(ptr: *mut libc::c_void);
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: size_t)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void,
              _: size_t) -> libc::c_int;
    #[no_mangle]
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> size_t;
    /* Store zero terminated CRAM-MD5 challenge in output buffer.  The
   CHALLENGE buffer must be allocated by the caller, and must have
   room for CRAM_MD5_CHALLENGE_LEN characters.  Returns 0 on success,
   and -1 on randomness problems.  */
    #[no_mangle]
    fn cram_md5_challenge(challenge: *mut libc::c_char) -> libc::c_int;
    /* digest.h --- Generate a CRAM-MD5 hex encoded HMAC-MD5 response string.
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
    /* Get size_t. */
    /* Compute hex encoded HMAC-MD5 on the CHALLENGELEN long string
   CHALLENGE, keyed with SECRET of length SECRETLEN.  Use a
   CHALLENGELEN or SECRETLEN of 0 to indicate that CHALLENGE or
   SECRET, respectively, is zero terminated.  The RESPONSE buffer must
   be allocated by the caller, and must have room for
   CRAM_MD5_DIGEST_LEN characters.*/
    #[no_mangle]
    fn cram_md5_digest(challenge: *const libc::c_char, challengelen: size_t,
                       secret: *const libc::c_char, secretlen: size_t,
                       response: *mut libc::c_char);
}

#[no_mangle]
pub unsafe extern "C" fn _gsasl_cram_md5_server_start(mut sctx: *mut Gsasl_session,
                                                      mut mech_data: *mut *mut libc::c_void
    ) -> libc::c_int
{
    let mut challenge: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut rc: libc::c_int = 0;
    challenge =
        malloc(35) as *mut libc::c_char;
    if challenge.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    rc = cram_md5_challenge(challenge);
    if rc != 0 { return GSASL_CRYPTO_ERROR as libc::c_int }
    *mech_data = challenge as *mut libc::c_void;
    return GSASL_OK as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn _gsasl_cram_md5_server_step(mut sctx: *mut Gsasl_session,
                                                     mut mech_data: *mut libc::c_void,
                                                     mut input: *const libc::c_char,
                                                     mut input_len: size_t,
                                                     mut output: *mut *mut libc::c_char,
                                                     mut output_len: *mut size_t
    ) -> libc::c_int
{
    let mut challenge: *mut libc::c_char = mech_data as *mut libc::c_char;
    let mut hash: [libc::c_char; 32] = [0; 32];
    let mut password: *const libc::c_char = 0 as *const libc::c_char;
    let mut username: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut res: libc::c_int = GSASL_OK as libc::c_int;
    let mut normkey: *mut libc::c_char = 0 as *mut libc::c_char;
    if input_len == 0 {
        *output_len = strlen(challenge) as usize;
        *output = strdup(challenge);
        return GSASL_NEEDS_MORE as libc::c_int
    }
    if input_len <= (16 * 2) {
        return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
    }
    if *input.offset(input_len.wrapping_sub(16 * 2).wrapping_sub(1) as isize) != ' ' as i8 {
        return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
    }
    username = calloc(1, input_len.wrapping_sub(16 * 2)) as *mut libc::c_char;
    if username.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    memcpy(username as *mut libc::c_void, input as *const libc::c_void,
           input_len.wrapping_sub(16 * 2).wrapping_sub(1));
    res = gsasl_property_set(sctx, GSASL_AUTHID, username);
    rpl_free(username as *mut libc::c_void);
    if res != GSASL_OK as libc::c_int { return res }
    password = gsasl_property_get(sctx, GSASL_PASSWORD);
    if password.is_null() { return GSASL_NO_PASSWORD as libc::c_int }
    /* FIXME: Use SASLprep here?  Treat string as storage string?
     Specification is unclear. */
    res =
        gsasl_saslprep(password, 0 as Gsasl_saslprep_flags, &mut normkey,
                       0 as *mut libc::c_int);
    if res != GSASL_OK as libc::c_int { return res }
    cram_md5_digest(challenge, strlen(challenge) as usize, normkey, strlen(normkey) as usize,
                    hash.as_mut_ptr());
    rpl_free(normkey as *mut libc::c_void);
    if memcmp(&*input.offset(input_len.wrapping_sub(32) as isize)
                  as *const libc::c_char as *const libc::c_void,
              hash.as_mut_ptr() as *const libc::c_void,
              (2 * 16)) == 0
    {
        res = GSASL_OK as libc::c_int
    }
    else
    {
        res = GSASL_AUTHENTICATION_ERROR as libc::c_int
    }
    *output_len = 0 as libc::c_int as size_t;
    *output = 0 as *mut libc::c_char;
    return res;
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
#[no_mangle]
pub unsafe extern "C" fn _gsasl_cram_md5_server_finish(mut sctx: *mut Gsasl_session,
                                                       mut mech_data: *mut libc::c_void)
{
    let mut challenge: *mut libc::c_char = mech_data as *mut libc::c_char;
    rpl_free(challenge as *mut libc::c_void);
}
