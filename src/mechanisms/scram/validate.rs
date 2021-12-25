use ::libc;
use crate::mechanisms::scram::client::{scram_client_final, scram_client_first};
use crate::mechanisms::scram::server::{scram_server_final, scram_server_first};

extern "C" {
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
}
/* tokens.h --- Types for SCRAM tokens.
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

/* validate.c --- Validate consistency of SCRAM tokens.
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
/* Get strcmp, strlen. */
#[no_mangle]
pub unsafe fn scram_valid_client_first(mut cf: *mut scram_client_first) -> bool {
    /* Check that cbflag is one of permitted values. */
    match (*cf).cbflag as libc::c_int {
        112 | 110 | 121 => { }
        _ => { return 0 as libc::c_int != 0 }
    }
    /* Check that cbname is only set when cbflag is p. */
    if (*cf).cbflag as libc::c_int == 'p' as i32 && (*cf).cbname.is_null() {
        return 0 as libc::c_int != 0
    } else {
        if (*cf).cbflag as libc::c_int != 'p' as i32 &&
               !(*cf).cbname.is_null() {
            return 0 as libc::c_int != 0
        }
    }
    if !(*cf).cbname.is_null() {
        let mut p: *const libc::c_char = (*cf).cbname;
        while *p as libc::c_int != 0 &&
                  !strchr(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-\x00"
                              as *const u8 as *const libc::c_char,
                          *p as libc::c_int).is_null() {
            p = p.offset(1)
        }
        if *p != 0 { return 0 as libc::c_int != 0 }
    }
    /* We require a non-zero username string. */
    if (*cf).username.is_null() ||
           *(*cf).username as libc::c_int == '\u{0}' as i32 {
        return 0 as libc::c_int != 0
    }
    /* We require a non-zero client nonce. */
    if (*cf).client_nonce.is_null() ||
           *(*cf).client_nonce as libc::c_int == '\u{0}' as i32 {
        return 0 as libc::c_int != 0
    }
    /* Nonce cannot contain ','. */
    if !strchr((*cf).client_nonce, ',' as i32).is_null() {
        return 0 as libc::c_int != 0
    }
    return 1 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe fn scram_valid_server_first(mut sf: *mut scram_server_first) -> bool {
    /* We require a non-zero nonce. */
    if (*sf).nonce.is_null() || *(*sf).nonce as libc::c_int == '\u{0}' as i32
       {
        return 0 as libc::c_int != 0
    }
    /* Nonce cannot contain ','. */
    if !strchr((*sf).nonce, ',' as i32).is_null() {
        return 0 as libc::c_int != 0
    }
    /* We require a non-zero salt. */
    if (*sf).salt.is_null() || *(*sf).salt as libc::c_int == '\u{0}' as i32 {
        return 0 as libc::c_int != 0
    }
    /* FIXME check that salt is valid base64. */
    if !strchr((*sf).salt, ',' as i32).is_null() {
        return 0 as libc::c_int != 0
    }
    if (*sf).iter == 0 {
        return 0 as libc::c_int != 0
    }
    return 1 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe fn scram_valid_client_final(mut cl: *mut scram_client_final) -> bool {
    /* We require a non-zero cbind. */
    if (*cl).cbind.is_null() || *(*cl).cbind as libc::c_int == '\u{0}' as i32
       {
        return 0 as libc::c_int != 0
    }
    /* FIXME check that cbind is valid base64. */
    if !strchr((*cl).cbind, ',' as i32).is_null() {
        return 0 as libc::c_int != 0
    }
    /* We require a non-zero nonce. */
    if (*cl).nonce.is_null() || *(*cl).nonce as libc::c_int == '\u{0}' as i32
       {
        return 0 as libc::c_int != 0
    }
    /* Nonce cannot contain ','. */
    if !strchr((*cl).nonce, ',' as i32).is_null() {
        return 0 as libc::c_int != 0
    }
    /* We require a non-zero proof. */
    if (*cl).proof.is_null() || *(*cl).proof as libc::c_int == '\u{0}' as i32
       {
        return 0 as libc::c_int != 0
    }
    /* FIXME check that proof is valid base64. */
    if !strchr((*cl).proof, ',' as i32).is_null() {
        return 0 as libc::c_int != 0
    }
    return 1 as libc::c_int != 0;
}
/* validate.h --- Validate consistency of SCRAM tokens.
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
/* Get bool. */
#[no_mangle]
pub unsafe fn scram_valid_server_final(mut sl: *mut scram_server_final) -> bool {
    /* We require a non-zero verifier. */
    if (*sl).verifier.is_null() ||
           *(*sl).verifier as libc::c_int == '\u{0}' as i32 {
        return 0 as libc::c_int != 0
    }
    /* FIXME check that verifier is valid base64. */
    if !strchr((*sl).verifier, ',' as i32).is_null() {
        return 0 as libc::c_int != 0
    }
    return 1 as libc::c_int != 0;
}
