use ::libc;
use libc::size_t;
use crate::callback::gsasl_callback;
use crate::consts::{GSASL_AUTHENTICATION_ERROR, GSASL_AUTHID, GSASL_AUTHZID, GSASL_MALLOC_ERROR, GSASL_MECHANISM_PARSE_ERROR, GSASL_NEEDS_MORE, GSASL_NO_CALLBACK, GSASL_NO_PASSWORD, GSASL_OK, GSASL_PASSWORD, GSASL_VALIDATE_SIMPLE};
use crate::gsasl::{Gsasl, Gsasl_session};
use crate::property::{gsasl_property_free, gsasl_property_get, gsasl_property_set};
use crate::saslprep::{GSASL_ALLOW_UNASSIGNED, gsasl_saslprep, Gsasl_saslprep_flags};

extern "C" {
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: size_t)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memchr(_: *const libc::c_void, _: libc::c_int, _: size_t)
     -> *mut libc::c_void;
    #[no_mangle]
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> size_t;
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
    fn rpl_free(_: *mut libc::c_void);
    #[no_mangle]
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

/* server.c --- SASL mechanism PLAIN as defined in RFC 2595, server side.
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
/* Get memcpy, memchr, strlen. */
/* Get malloc, free. */
#[no_mangle]
pub unsafe extern "C" fn _gsasl_plain_server_step(mut sctx: *mut Gsasl_session,
                                                  mut mech_data: *mut libc::c_void,
                                                  mut input: *const libc::c_char,
                                                  mut input_len: size_t,
                                                  mut output: *mut *mut libc::c_char,
                                                  mut output_len: *mut size_t
    ) -> libc::c_int
{
    let mut authzidptr: *const libc::c_char = input;
    let mut authidptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut passwordptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut passwdz: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut passprep: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut authidprep: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut res: libc::c_int = 0;
    *output_len = 0 as libc::c_int as size_t;
    *output = 0 as *mut libc::c_char;
    if input_len == 0 {
        return GSASL_NEEDS_MORE as libc::c_int
    }
    /* Parse input. */
    let mut tmplen: size_t = 0;
    authidptr = memchr(input as *const libc::c_void, 0, input_len.wrapping_sub(1))
        as *mut libc::c_char;
    if !authidptr.is_null() {
        authidptr = authidptr.offset(1);
        passwordptr = memchr(authidptr as *const libc::c_void, 0,
                             input_len.wrapping_sub(strlen(input))
                                      .wrapping_sub(1))
            as *mut libc::c_char;
        if !passwordptr.is_null() {
            passwordptr = passwordptr.offset(1)
        } else { return GSASL_MECHANISM_PARSE_ERROR as libc::c_int }
    } else { return GSASL_MECHANISM_PARSE_ERROR as libc::c_int }
    /* As the NUL (U+0000) character is used as a deliminator, the NUL
       (U+0000) character MUST NOT appear in authzid, authcid, or passwd
       productions. */
    tmplen =
        input_len.wrapping_sub(passwordptr.wrapping_offset_from(input) as
                                   libc::c_long as size_t);
    if !memchr(passwordptr as *const libc::c_void, 0 as libc::c_int,
               tmplen).is_null() {
        return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
    }
    /* Store authid, after preparing it... */
    res =
        gsasl_saslprep(authidptr, GSASL_ALLOW_UNASSIGNED, &mut authidprep,
                       0 as *mut libc::c_int);
    if res != GSASL_OK as libc::c_int { return res }
    res = gsasl_property_set(sctx, GSASL_AUTHID, authidprep);
    if res != GSASL_OK as libc::c_int { return res }
    /* Store authzid, if absent, use SASLprep(authcid). */
    if *authzidptr as libc::c_int == '\u{0}' as i32 {
        res = gsasl_property_set(sctx, GSASL_AUTHZID, authidprep)
    } else { res = gsasl_property_set(sctx, GSASL_AUTHZID, authzidptr) }
    if res != GSASL_OK as libc::c_int { return res }
    rpl_free(authidprep as *mut libc::c_void);
    /* Store passwd, after preparing it... */
    let mut passwdzlen: size_t =
        input_len.wrapping_sub(passwordptr.wrapping_offset_from(input) as
                                   libc::c_long as size_t);
    /* Need to zero terminate password... */
    passwdz = malloc(passwdzlen.wrapping_add(1)) as *mut libc::c_char;
    if passwdz.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    memcpy(passwdz as *mut libc::c_void, passwordptr as *const libc::c_void,
           passwdzlen);
    *passwdz.offset(passwdzlen as isize) = '\u{0}' as i32 as libc::c_char;
    res =
        gsasl_saslprep(passwdz, GSASL_ALLOW_UNASSIGNED, &mut passprep,
                       0 as *mut libc::c_int);
    rpl_free(passwdz as *mut libc::c_void);
    if res != GSASL_OK as libc::c_int { return res }
    res = gsasl_property_set(sctx, GSASL_PASSWORD, passprep);
    if res != GSASL_OK as libc::c_int { return res }
    /* Authorization.  Let application verify credentials internally,
     but fall back to deal with it locally... */
    res = gsasl_callback(0 as *mut Gsasl, sctx, GSASL_VALIDATE_SIMPLE);
    if res == GSASL_NO_CALLBACK as libc::c_int {
        let mut key: *const libc::c_char = 0 as *const libc::c_char;
        let mut normkey: *mut libc::c_char = 0 as *mut libc::c_char;
        gsasl_property_free(sctx, GSASL_PASSWORD);
        /* The following will invoke a GSASL_PASSWORD callback. */
        key = gsasl_property_get(sctx, GSASL_PASSWORD);
        if key.is_null() {
            rpl_free(passprep as *mut libc::c_void);
            return GSASL_NO_PASSWORD as libc::c_int
        }
        /* Unassigned code points are not permitted. */
        res =
            gsasl_saslprep(key, 0 as Gsasl_saslprep_flags, &mut normkey,
                           0 as *mut libc::c_int);
        if res != GSASL_OK as libc::c_int {
            rpl_free(passprep as *mut libc::c_void);
            return res
        }
        if strcmp(normkey, passprep) == 0 as libc::c_int {
            res = GSASL_OK as libc::c_int
        } else { res = GSASL_AUTHENTICATION_ERROR as libc::c_int }
        rpl_free(normkey as *mut libc::c_void);
    }
    rpl_free(passprep as *mut libc::c_void);
    return res;
}
