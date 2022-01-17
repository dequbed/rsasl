use ::libc;
use libc::{strcmp, strlen};
use crate::mechanisms::digest_md5::parser::{digest_md5_challenge, digest_md5_finish, digest_md5_response};
use crate::mechanisms::digest_md5::qop::{DIGEST_MD5_QOP_AUTH, DIGEST_MD5_QOP_AUTH_CONF};

/* validate.c --- Validate consistency of DIGEST-MD5 tokens.
 * Copyright (C) 2004-2021 Simon Josefsson
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
pub unsafe fn digest_md5_validate_challenge(mut c: *mut digest_md5_challenge)
 -> libc::c_int {
    /* This directive is required and MUST appear exactly once; if
     not present, or if multiple instances are present, the
     client should abort the authentication exchange. */
    if (*c).nonce.is_null() { return -(1 as libc::c_int) }
    /* This directive must be present exactly once if "auth-conf" is
     offered in the "qop-options" directive */
    if (*c).ciphers != 0 &&
           (*c).qops & DIGEST_MD5_QOP_AUTH_CONF as libc::c_int == 0 {
        return -(1 as libc::c_int)
    }
    if (*c).ciphers == 0 &&
           (*c).qops & DIGEST_MD5_QOP_AUTH_CONF as libc::c_int != 0 {
        return -(1 as libc::c_int)
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe fn digest_md5_validate_response(mut r: *mut digest_md5_response)
 -> libc::c_int {
    /* This directive is required and MUST be present exactly
     once; otherwise, authentication fails. */
    if (*r).username.is_null() { return -(1 as libc::c_int) }
    /* This directive is required and MUST be present exactly
     once; otherwise, authentication fails. */
    if (*r).nonce.is_null() { return -(1 as libc::c_int) }
    /* This directive is required and MUST be present exactly once;
     otherwise, authentication fails. */
    if (*r).cnonce.is_null() { return -(1 as libc::c_int) }
    /* This directive is required and MUST be present exactly once;
     otherwise, or if the value is 0, authentication fails. */
    if (*r).nc == 0 { return -(1 as libc::c_int) }
    /* This directive is required and MUST be present exactly
     once; if multiple instances are present, the client MUST
     abort the authentication exchange. */
    if (*r).digesturi.is_null() { return -(1 as libc::c_int) }
    /* This directive is required and MUST be present exactly
     once; otherwise, authentication fails. */
    if *(*r).response.as_mut_ptr() == 0 { return -(1 as libc::c_int) }
    if strlen((*r).response.as_mut_ptr()) != 32 {
        return -(1 as libc::c_int)
    }
    /* This directive MUST appear exactly once if "auth-conf" is
     negotiated; if required and not present, authentication fails.
     If the client recognizes no cipher and the server only advertised
     "auth-conf" in the qop option, the client MUST abort the
     authentication exchange.  */
    if (*r).qop as libc::c_uint ==
           DIGEST_MD5_QOP_AUTH_CONF as libc::c_int as libc::c_uint &&
           (*r).cipher as u64 == 0 {
        return -(1 as libc::c_int)
    }
    if (*r).qop as libc::c_uint !=
           DIGEST_MD5_QOP_AUTH_CONF as libc::c_int as libc::c_uint &&
           (*r).cipher as libc::c_uint != 0 {
        return -(1 as libc::c_int)
    }
    return 0 as libc::c_int;
}
/* validate.h --- Validate consistency of DIGEST-MD5 tokens.
 * Copyright (C) 2004-2021 Simon Josefsson
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
#[no_mangle]
pub unsafe fn digest_md5_validate_finish(mut f: *mut digest_md5_finish)
 -> libc::c_int {
    if (*f).rspauth.as_mut_ptr().is_null() { return -(1 as libc::c_int) }
    /* A string of 32 hex digits */
    if strlen((*f).rspauth.as_mut_ptr()) != 32 {
        return -(1 as libc::c_int)
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe fn digest_md5_validate(mut c: *mut digest_md5_challenge,
                                             mut r: *mut digest_md5_response)
 -> libc::c_int {
    if (*c).nonce.is_null() || (*r).nonce.is_null() {
        return -(1 as libc::c_int)
    }
    if strcmp((*c).nonce, (*r).nonce) != 0 as libc::c_int {
        return -(1 as libc::c_int)
    }
    if (*r).nc != 1 {
        return -(1 as libc::c_int)
    }
    if (*c).utf8 == 0 && (*r).utf8 != 0 { return -(1 as libc::c_int) }
    if (if (*c).qops != 0 {
            (*c).qops
        } else { DIGEST_MD5_QOP_AUTH as libc::c_int }) as libc::c_uint &
           (if (*r).qop as libc::c_uint != 0 {
                (*r).qop as libc::c_uint
            } else { DIGEST_MD5_QOP_AUTH as libc::c_int as libc::c_uint }) ==
           0 {
        return -(1 as libc::c_int)
    }
    if (*r).qop as libc::c_uint &
           DIGEST_MD5_QOP_AUTH_CONF as libc::c_int as libc::c_uint != 0 &&
           (*c).ciphers as libc::c_uint & (*r).cipher as libc::c_uint == 0 {
        return -(1 as libc::c_int)
    }
    /* FIXME: Check more? */
    return 0 as libc::c_int;
}
