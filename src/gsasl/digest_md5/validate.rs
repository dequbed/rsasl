use ::libc;
use libc::size_t;
extern "C" {
    #[no_mangle]
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> size_t;
}

/* tokens.h --- Types for DIGEST-MD5 tokens.
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
/* Get size_t. */
/* Length of MD5 output. */
/* Quality of Protection types. */
pub type digest_md5_qop = libc::c_uint;
pub const DIGEST_MD5_QOP_AUTH_CONF: digest_md5_qop = 4;
pub const DIGEST_MD5_QOP_AUTH_INT: digest_md5_qop = 2;
pub const DIGEST_MD5_QOP_AUTH: digest_md5_qop = 1;
/* Cipher types. */
pub type digest_md5_cipher = libc::c_uint;
pub const DIGEST_MD5_CIPHER_AES_CBC: digest_md5_cipher = 32;
pub const DIGEST_MD5_CIPHER_RC4_56: digest_md5_cipher = 16;
pub const DIGEST_MD5_CIPHER_RC4_40: digest_md5_cipher = 8;
pub const DIGEST_MD5_CIPHER_RC4: digest_md5_cipher = 4;
pub const DIGEST_MD5_CIPHER_3DES: digest_md5_cipher = 2;
pub const DIGEST_MD5_CIPHER_DES: digest_md5_cipher = 1;
/*
 * digest-challenge  =
 *       1#( realm | nonce | qop-options | stale | server_maxbuf | charset
 *             algorithm | cipher-opts | auth-param )
 *
 * realm             = "realm" "=" <"> realm-value <">
 * realm-value       = qdstr-val
 * nonce             = "nonce" "=" <"> nonce-value <">
 * nonce-value       = *qdtext
 * qop-options       = "qop" "=" <"> qop-list <">
 * qop-list          = 1#qop-value
 * qop-value         = "auth" | "auth-int" | "auth-conf" | qop-token
 *                    ;; qop-token is reserved for identifying future
 *                    ;; extensions to DIGEST-MD5
 * qop-token         = token
 * stale             = "stale" "=" "true"
 * server_maxbuf     = "maxbuf" "=" maxbuf-value
 * maxbuf-value      = 1*DIGIT
 * charset           = "charset" "=" "utf-8"
 * algorithm         = "algorithm" "=" "md5-sess"
 * cipher-opts       = "cipher" "=" <"> 1#cipher-value <">
 * cipher-value      = "3des" | "des" | "rc4-40" | "rc4" |
 *                     "rc4-56" | "aes-cbc" | cipher-token
 *                     ;; "des" and "3des" ciphers are obsolete.
 *                     ;; cipher-token is reserved for new ciphersuites
 * cipher-token      = token
 * auth-param        = token "=" ( token | quoted-string )
 *
 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct digest_md5_challenge {
    pub nrealms: size_t,
    pub realms: *mut *mut libc::c_char,
    pub nonce: *mut libc::c_char,
    pub qops: libc::c_int,
    pub stale: libc::c_int,
    pub servermaxbuf: size_t,
    pub utf8: libc::c_int,
    pub ciphers: libc::c_int,
}
/*
 * digest-response  = 1#( username | realm | nonce | cnonce |
 *                        nonce-count | qop | digest-uri | response |
 *                        client_maxbuf | charset | cipher | authzid |
 *                        auth-param )
 *
 *     username         = "username" "=" <"> username-value <">
 *     username-value   = qdstr-val
 *     cnonce           = "cnonce" "=" <"> cnonce-value <">
 *     cnonce-value     = *qdtext
 *     nonce-count      = "nc" "=" nc-value
 *     nc-value         = 8LHEX
 *     client_maxbuf    = "maxbuf" "=" maxbuf-value
 *     qop              = "qop" "=" qop-value
 *     digest-uri       = "digest-uri" "=" <"> digest-uri-value <">
 *     digest-uri-value  = serv-type "/" host [ "/" serv-name ]
 *     serv-type        = 1*ALPHA
 *     serv-name        = host
 *     response         = "response" "=" response-value
 *     response-value   = 32LHEX
 *     LHEX             = "0" | "1" | "2" | "3" |
 *                        "4" | "5" | "6" | "7" |
 *                        "8" | "9" | "a" | "b" |
 *                        "c" | "d" | "e" | "f"
 *     cipher           = "cipher" "=" cipher-value
 *     authzid          = "authzid" "=" <"> authzid-value <">
 *     authzid-value    = qdstr-val
 *
 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct digest_md5_response {
    pub username: *mut libc::c_char,
    pub realm: *mut libc::c_char,
    pub nonce: *mut libc::c_char,
    pub cnonce: *mut libc::c_char,
    pub nc: size_t,
    pub qop: digest_md5_qop,
    pub digesturi: *mut libc::c_char,
    pub clientmaxbuf: size_t,
    pub utf8: libc::c_int,
    pub cipher: digest_md5_cipher,
    pub authzid: *mut libc::c_char,
    pub response: [libc::c_char; 33],
}
/*
 * response-auth = "rspauth" "=" response-value
 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct digest_md5_finish {
    pub rspauth: [libc::c_char; 33],
}
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
pub unsafe extern "C" fn digest_md5_validate_challenge(mut c:
                                                           *mut digest_md5_challenge)
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
pub unsafe extern "C" fn digest_md5_validate_response(mut r:
                                                          *mut digest_md5_response)
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
pub unsafe extern "C" fn digest_md5_validate_finish(mut f:
                                                        *mut digest_md5_finish)
 -> libc::c_int {
    if (*f).rspauth.as_mut_ptr().is_null() { return -(1 as libc::c_int) }
    /* A string of 32 hex digits */
    if strlen((*f).rspauth.as_mut_ptr()) != 32 {
        return -(1 as libc::c_int)
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn digest_md5_validate(mut c: *mut digest_md5_challenge,
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
