use ::libc;
use libc::size_t;
use crate::gsasl::scram::client::{scram_client_final, scram_client_first};
use crate::gsasl::scram::server::{scram_server_final, scram_server_first};
use crate::gsasl::scram::validate::{scram_valid_client_final, scram_valid_client_first, scram_valid_server_final, scram_valid_server_first};

extern "C" {
    fn malloc(_: size_t) -> *mut libc::c_void;
    fn rpl_free(ptr: *mut libc::c_void);
    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char, _: ...) -> libc::c_int;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: size_t) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> size_t;
}

/* printer.h --- Convert SCRAM token structures into strings.
 * Copyright (C) 2009-2021 Simon Josefsson
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
/* Get prototypes. */
/* Get free. */
/* Get asprintf. */
/* Get strdup. */
/* Get token validator. */
unsafe extern "C" fn scram_escape(mut str: *const libc::c_char)
 -> *mut libc::c_char {
    let mut out: *mut libc::c_char =
        malloc(strlen(str).wrapping_mul(3).wrapping_add(1)) as *mut libc::c_char;

    let mut p: *mut libc::c_char = out;
    if out.is_null() { return 0 as *mut libc::c_char }
    while *str != 0 {
        if *str as libc::c_int == ',' as i32 {
            memcpy(p as *mut libc::c_void,
                   b"=2C\x00" as *const u8 as *const libc::c_void,
                   3);

            p = p.offset(3)
        } else if *str as libc::c_int == '=' as i32 {
            memcpy(p as *mut libc::c_void,
                   b"=3D\x00" as *const u8 as *const libc::c_void,
                   3);

            p = p.offset(3 as libc::c_int as isize)
        } else {
            *p = *str;
            p = p.offset(1)
        }
        str = str.offset(1)
    }
    *p = '\u{0}' as i32 as libc::c_char;
    return out;
}
/* printer.h --- Convert SCRAM token structures into strings.
 * Copyright (C) 2009-2021 Simon Josefsson
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
/* Get token types. */
/* Print SCRAM client-first token into newly allocated output string
   OUT.  Returns 0 on success, -1 on invalid token, and -2 on memory
   allocation errors. */
#[no_mangle]
pub unsafe extern "C" fn scram_print_client_first(
    mut cf: *mut scram_client_first,
    mut out: *mut *mut libc::c_char
) -> libc::c_int {
    let mut username: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut authzid: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut n: libc::c_int = 0;
    /* Below we assume fields are sensible, so first verify that to
     avoid crashes. */
    if !scram_valid_client_first(cf) { return -(1 as libc::c_int) }
    /* Escape username and authzid. */
    username = scram_escape((*cf).username);
    if username.is_null() { return -(2 as libc::c_int) }
    if !(*cf).authzid.is_null() {
        authzid = scram_escape((*cf).authzid);
        if authzid.is_null() { return -(2 as libc::c_int) }
    }
    n =
        asprintf(out,
                 b"%c%s%s,%s%s,n=%s,r=%s\x00" as *const u8 as
                     *const libc::c_char, (*cf).cbflag as libc::c_int,
                 if (*cf).cbflag as libc::c_int == 'p' as i32 {
                     b"=\x00" as *const u8 as *const libc::c_char
                 } else { b"\x00" as *const u8 as *const libc::c_char },
                 if (*cf).cbflag as libc::c_int == 'p' as i32 {
                     (*cf).cbname
                 } else { b"\x00" as *const u8 as *const libc::c_char },
                 if !authzid.is_null() {
                     b"a=\x00" as *const u8 as *const libc::c_char
                 } else { b"\x00" as *const u8 as *const libc::c_char },
                 if !authzid.is_null() {
                     authzid
                 } else { b"\x00" as *const u8 as *const libc::c_char },
                 username, (*cf).client_nonce);
    rpl_free(username as *mut libc::c_void);
    rpl_free(authzid as *mut libc::c_void);
    if n <= 0 as libc::c_int || (*out).is_null() {
        return -(1 as libc::c_int)
    }
    return 0 as libc::c_int;
}
/* Print SCRAM server-first token into newly allocated output string
   OUT.  Returns 0 on success, -1 on invalid token, and -2 on memory
   allocation errors. */
#[no_mangle]
pub unsafe extern "C" fn scram_print_server_first(
    mut sf: *mut scram_server_first,
    mut out: *mut *mut libc::c_char
) -> libc::c_int {
    let mut n: libc::c_int = 0;
    /* Below we assume fields are sensible, so first verify that to
     avoid crashes. */
    if !scram_valid_server_first(sf) { return -(1 as libc::c_int) }
    n =
        asprintf(out,
                 b"r=%s,s=%s,i=%lu\x00" as *const u8 as *const libc::c_char,
                 (*sf).nonce, (*sf).salt, (*sf).iter);
    if n <= 0 as libc::c_int || (*out).is_null() {
        return -(1 as libc::c_int)
    }
    return 0 as libc::c_int;
}
/* Print SCRAM client-final token into newly allocated output string
   OUT.  Returns 0 on success, -1 on invalid token, and -2 on memory
   allocation errors. */
#[no_mangle]
pub unsafe extern "C" fn scram_print_client_final(
    mut cl: *mut scram_client_final,
    mut out: *mut *mut libc::c_char
) -> libc::c_int {
    let mut n: libc::c_int = 0;
    /* Below we assume fields are sensible, so first verify that to
     avoid crashes. */
    if !scram_valid_client_final(cl) { return -(1 as libc::c_int) }
    n =
        asprintf(out,
                 b"c=%s,r=%s,p=%s\x00" as *const u8 as *const libc::c_char,
                 (*cl).cbind, (*cl).nonce, (*cl).proof);
    if n <= 0 as libc::c_int || (*out).is_null() {
        return -(1 as libc::c_int)
    }
    return 0 as libc::c_int;
}
/* Print SCRAM server-final token into newly allocated output string
   OUT.  Returns 0 on success, -1 on invalid token, and -2 on memory
   allocation errors. */
#[no_mangle]
pub unsafe extern "C" fn scram_print_server_final(
    mut sl: *mut scram_server_final,
    mut out: *mut *mut libc::c_char,
)
    -> libc::c_int {
    let mut n: libc::c_int = 0;
    /* Below we assume fields are sensible, so first verify that to
     avoid crashes. */
    if !scram_valid_server_final(sl) { return -(1 as libc::c_int) }
    n =
        asprintf(out, b"v=%s\x00" as *const u8 as *const libc::c_char,
                 (*sl).verifier);
    if n <= 0 as libc::c_int || (*out).is_null() {
        return -(1 as libc::c_int)
    }
    return 0 as libc::c_int;
}
