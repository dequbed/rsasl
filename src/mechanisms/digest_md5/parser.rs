use crate::gsasl::gl::free::rpl_free;
use crate::mechanisms::digest_md5::getsubopt::digest_md5_getsubopt;
use crate::mechanisms::digest_md5::qop::{
    digest_md5_qop, DIGEST_MD5_QOP_AUTH, DIGEST_MD5_QOP_AUTH_CONF, DIGEST_MD5_QOP_AUTH_INT,
};
use crate::mechanisms::digest_md5::validate::{
    digest_md5_validate_challenge, digest_md5_validate_finish, digest_md5_validate_response,
};
use ::libc;
use libc::{memset, realloc, size_t, strcmp, strcpy, strdup, strlen, strndup, strtoul};

pub type digest_md5_cipher = libc::c_uint;
pub const DIGEST_MD5_CIPHER_AES_CBC: digest_md5_cipher = 32;
pub const DIGEST_MD5_CIPHER_RC4_56: digest_md5_cipher = 16;
pub const DIGEST_MD5_CIPHER_RC4_40: digest_md5_cipher = 8;
pub const DIGEST_MD5_CIPHER_RC4: digest_md5_cipher = 4;
pub const DIGEST_MD5_CIPHER_3DES: digest_md5_cipher = 2;
pub const DIGEST_MD5_CIPHER_DES: digest_md5_cipher = 1;
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
/* Cipher types. */
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
/*
 * response-auth = "rspauth" "=" response-value
 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct digest_md5_finish {
    pub rspauth: [libc::c_char; 33],
}
pub const CIPHER_AES_CBC: C2RustUnnamed_1 = 5;
pub const CIPHER_RC4_56: C2RustUnnamed_1 = 4;
pub const CIPHER_RC4_40: C2RustUnnamed_1 = 3;
pub const CIPHER_RC4: C2RustUnnamed_1 = 2;
pub const CIPHER_3DES: C2RustUnnamed_1 = 1;
/* the order must match the following struct */
pub const CIPHER_DES: C2RustUnnamed_1 = 0;
pub const CHALLENGE_CIPHER: C2RustUnnamed = 7;
pub const CHALLENGE_ALGORITHM: C2RustUnnamed = 6;
pub const CHALLENGE_CHARSET: C2RustUnnamed = 5;
pub const CHALLENGE_MAXBUF: C2RustUnnamed = 4;
pub const CHALLENGE_STALE: C2RustUnnamed = 3;
pub const QOP_AUTH_CONF: C2RustUnnamed_0 = 2;
pub const QOP_AUTH_INT: C2RustUnnamed_0 = 1;
/* the order must match the following struct */
pub const QOP_AUTH: C2RustUnnamed_0 = 0;
pub const CHALLENGE_QOP: C2RustUnnamed = 2;
pub const CHALLENGE_NONCE: C2RustUnnamed = 1;
/* the order must match the following struct */
pub const CHALLENGE_REALM: C2RustUnnamed = 0;
pub const RESPONSE_AUTHZID: C2RustUnnamed_2 = 11;
pub const RESPONSE_CIPHER: C2RustUnnamed_2 = 10;
pub const RESPONSE_CHARSET: C2RustUnnamed_2 = 9;
pub const RESPONSE_MAXBUF: C2RustUnnamed_2 = 8;
pub const RESPONSE_RESPONSE: C2RustUnnamed_2 = 7;
pub const RESPONSE_DIGEST_URI: C2RustUnnamed_2 = 6;
pub const RESPONSE_QOP: C2RustUnnamed_2 = 5;
pub const RESPONSE_NC: C2RustUnnamed_2 = 4;
pub const RESPONSE_CNONCE: C2RustUnnamed_2 = 3;
pub const RESPONSE_NONCE: C2RustUnnamed_2 = 2;
pub const RESPONSE_REALM: C2RustUnnamed_2 = 1;
/* the order must match the following struct */
pub const RESPONSE_USERNAME: C2RustUnnamed_2 = 0;
/* the order must match the following struct */
pub const RESPONSEAUTH_RSPAUTH: C2RustUnnamed_3 = 0;
pub type C2RustUnnamed = libc::c_uint;
/* qop-value         = "auth" | "auth-int" | "auth-conf" | qop-token */
pub type C2RustUnnamed_0 = libc::c_uint;
/* cipher-value      = "3des" | "des" | "rc4-40" | "rc4" |
 *                     "rc4-56" | "aes-cbc" | cipher-token
 *                     ;; "des" and "3des" ciphers are obsolete.
 */
pub type C2RustUnnamed_1 = libc::c_uint;
pub type C2RustUnnamed_2 = libc::c_uint;
pub type C2RustUnnamed_3 = libc::c_uint;
static mut digest_challenge_opts: [*const libc::c_char; 9] = [
    b"realm\x00" as *const u8 as *const libc::c_char,
    b"nonce\x00" as *const u8 as *const libc::c_char,
    b"qop\x00" as *const u8 as *const libc::c_char,
    b"stale\x00" as *const u8 as *const libc::c_char,
    b"maxbuf\x00" as *const u8 as *const libc::c_char,
    b"charset\x00" as *const u8 as *const libc::c_char,
    b"algorithm\x00" as *const u8 as *const libc::c_char,
    b"cipher\x00" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut qop_opts: [*const libc::c_char; 4] = [
    b"auth\x00" as *const u8 as *const libc::c_char,
    b"auth-int\x00" as *const u8 as *const libc::c_char,
    b"auth-conf\x00" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut cipher_opts: [*const libc::c_char; 7] = [
    b"des\x00" as *const u8 as *const libc::c_char,
    b"3des\x00" as *const u8 as *const libc::c_char,
    b"rc4\x00" as *const u8 as *const libc::c_char,
    b"rc4-40\x00" as *const u8 as *const libc::c_char,
    b"rc4-56\x00" as *const u8 as *const libc::c_char,
    b"aes-cbc\x00" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
unsafe fn parse_challenge(
    mut challenge: *mut libc::c_char,
    mut out: *mut digest_md5_challenge,
) -> libc::c_int {
    let mut done_algorithm: libc::c_int = 0 as libc::c_int;
    let mut disable_qop_auth_conf: libc::c_int = 0 as libc::c_int;
    let mut value: *mut libc::c_char = 0 as *mut libc::c_char;
    memset(
        out as *mut libc::c_void,
        0,
        ::std::mem::size_of::<digest_md5_challenge>(),
    );
    /* The size of a digest-challenge MUST be less than 2048 bytes. */
    if strlen(challenge) >= 2048 {
        return -(1 as libc::c_int);
    }
    while *challenge as libc::c_int != '\u{0}' as i32 {
        match digest_md5_getsubopt(&mut challenge, digest_challenge_opts.as_ptr(), &mut value) {
            0 => {
                let mut tmp: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
                (*out).nrealms = (*out).nrealms.wrapping_add(1);
                tmp = realloc(
                    (*out).realms as *mut libc::c_void,
                    (*out)
                        .nrealms
                        .wrapping_mul(::std::mem::size_of::<*mut libc::c_char>()),
                ) as *mut *mut libc::c_char;
                if tmp.is_null() {
                    return -(1 as libc::c_int);
                }
                (*out).realms = tmp;
                let ref mut fresh0 = *(*out)
                    .realms
                    .offset((*out).nrealms.wrapping_sub(1) as isize);
                *fresh0 = strdup(value);
                if (*(*out)
                    .realms
                    .offset((*out).nrealms.wrapping_sub(1) as isize))
                .is_null()
                {
                    return -(1 as libc::c_int);
                }
            }
            1 => {
                /* This directive is required and MUST appear exactly once; if
                not present, or if multiple instances are present, the
                client should abort the authentication exchange. */
                if !(*out).nonce.is_null() {
                    return -(1 as libc::c_int);
                }
                (*out).nonce = strdup(value);
                if (*out).nonce.is_null() {
                    return -(1 as libc::c_int);
                }
            }
            2 => {
                /* <<What if this directive is present multiple times? Error,
                or take the union of all values?>> */
                if (*out).qops != 0 {
                    return -(1 as libc::c_int);
                }
                let mut subsubopts: *mut libc::c_char = 0 as *mut libc::c_char;
                let mut val: *mut libc::c_char = 0 as *mut libc::c_char;
                subsubopts = value;
                while *subsubopts as libc::c_int != '\u{0}' as i32 {
                    match digest_md5_getsubopt(&mut subsubopts, qop_opts.as_ptr(), &mut val) {
                        0 => (*out).qops |= DIGEST_MD5_QOP_AUTH as libc::c_int,
                        1 => (*out).qops |= DIGEST_MD5_QOP_AUTH_INT as libc::c_int,
                        2 => (*out).qops |= DIGEST_MD5_QOP_AUTH_CONF as libc::c_int,
                        _ => {}
                    }
                }
                /* if the client recognizes no cipher, it MUST behave as if
                "auth-conf" qop option wasn't provided by the server. */
                if disable_qop_auth_conf != 0 {
                    (*out).qops &= !(DIGEST_MD5_QOP_AUTH_CONF as libc::c_int)
                }
                /* if the client recognizes no option, it MUST abort the
                authentication exchange. */
                if (*out).qops == 0 {
                    return -(1 as libc::c_int);
                }
            }
            3 => {
                /* This directive may appear at most once; if multiple
                instances are present, the client MUST abort the
                authentication exchange. */
                if (*out).stale != 0 {
                    return -(1 as libc::c_int);
                }
                (*out).stale = 1 as libc::c_int
            }
            4 => {
                /* This directive may appear at most once; if multiple
                instances are present, or the value is out of range the
                client MUST abort the authentication exchange. */
                if (*out).servermaxbuf != 0 {
                    return -(1 as libc::c_int);
                }
                (*out).servermaxbuf = strtoul(value, 0 as *mut *mut libc::c_char, 10) as usize;
                /* FIXME: error handling. */
                /* The value MUST be bigger than 16 (32 for Confidentiality
                protection with the "aes-cbc" cipher) and smaller or equal
                to 16777215 (i.e. 2**24-1). */
                if (*out).servermaxbuf <= 16 || (*out).servermaxbuf > 16777215 {
                    return -(1 as libc::c_int);
                }
            }
            5 => {
                /* This directive may appear at most once; if multiple
                instances are present, the client MUST abort the
                authentication exchange. */
                if (*out).utf8 != 0 {
                    return -(1 as libc::c_int);
                }
                if strcmp(b"utf-8\x00" as *const u8 as *const libc::c_char, value)
                    != 0 as libc::c_int
                {
                    return -(1 as libc::c_int);
                }
                (*out).utf8 = 1 as libc::c_int
            }
            6 => {
                /* This directive is required and MUST appear exactly once; if
                not present, or if multiple instances are present, the
                client SHOULD abort the authentication exchange. */
                if done_algorithm != 0 {
                    return -(1 as libc::c_int);
                }
                if strcmp(b"md5-sess\x00" as *const u8 as *const libc::c_char, value)
                    != 0 as libc::c_int
                {
                    return -(1 as libc::c_int);
                }
                done_algorithm = 1 as libc::c_int
            }
            7 => {
                /* This directive must be present exactly once if "auth-conf"
                is offered in the "qop-options" directive */
                if (*out).ciphers != 0 {
                    return -(1 as libc::c_int);
                }
                let mut subsubopts_0: *mut libc::c_char = 0 as *mut libc::c_char;
                let mut val_0: *mut libc::c_char = 0 as *mut libc::c_char;
                subsubopts_0 = value;
                while *subsubopts_0 as libc::c_int != '\u{0}' as i32 {
                    match digest_md5_getsubopt(&mut subsubopts_0, cipher_opts.as_ptr(), &mut val_0)
                    {
                        0 => (*out).ciphers |= DIGEST_MD5_CIPHER_DES as libc::c_int,
                        1 => (*out).ciphers |= DIGEST_MD5_CIPHER_3DES as libc::c_int,
                        2 => (*out).ciphers |= DIGEST_MD5_CIPHER_RC4 as libc::c_int,
                        3 => (*out).ciphers |= DIGEST_MD5_CIPHER_RC4_40 as libc::c_int,
                        4 => (*out).ciphers |= DIGEST_MD5_CIPHER_RC4_56 as libc::c_int,
                        5 => (*out).ciphers |= DIGEST_MD5_CIPHER_AES_CBC as libc::c_int,
                        _ => {}
                    }
                }
                /* if the client recognizes no cipher, it MUST behave as if
                "auth-conf" qop option wasn't provided by the server. */
                if (*out).ciphers == 0 {
                    disable_qop_auth_conf = 1 as libc::c_int;
                    if (*out).qops != 0 {
                        /* if the client recognizes no option, it MUST abort the
                        authentication exchange. */
                        (*out).qops &= !(DIGEST_MD5_QOP_AUTH_CONF as libc::c_int);
                        if (*out).qops == 0 {
                            return -(1 as libc::c_int);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    /* This directive is required and MUST appear exactly once; if
    not present, or if multiple instances are present, the
    client SHOULD abort the authentication exchange. */
    if done_algorithm == 0 {
        return -(1 as libc::c_int);
    }
    /* Validate that we have the mandatory fields. */
    if digest_md5_validate_challenge(out) != 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
static mut digest_response_opts: [*const libc::c_char; 13] = [
    b"username\x00" as *const u8 as *const libc::c_char,
    b"realm\x00" as *const u8 as *const libc::c_char,
    b"nonce\x00" as *const u8 as *const libc::c_char,
    b"cnonce\x00" as *const u8 as *const libc::c_char,
    b"nc\x00" as *const u8 as *const libc::c_char,
    b"qop\x00" as *const u8 as *const libc::c_char,
    b"digest-uri\x00" as *const u8 as *const libc::c_char,
    b"response\x00" as *const u8 as *const libc::c_char,
    b"maxbuf\x00" as *const u8 as *const libc::c_char,
    b"charset\x00" as *const u8 as *const libc::c_char,
    b"cipher\x00" as *const u8 as *const libc::c_char,
    b"authzid\x00" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
unsafe fn parse_response(
    mut response: *mut libc::c_char,
    mut out: *mut digest_md5_response,
) -> libc::c_int {
    let mut value: *mut libc::c_char = 0 as *mut libc::c_char;
    memset(
        out as *mut libc::c_void,
        0,
        ::std::mem::size_of::<digest_md5_response>(),
    );
    /* The size of a digest-response MUST be less than 4096 bytes. */
    if strlen(response) >= 4096 {
        return -(1 as libc::c_int);
    }
    while *response as libc::c_int != '\u{0}' as i32 {
        match digest_md5_getsubopt(&mut response, digest_response_opts.as_ptr(), &mut value) {
            0 => {
                /* This directive is required and MUST be present exactly
                once; otherwise, authentication fails. */
                if !(*out).username.is_null() {
                    return -(1 as libc::c_int);
                }
                (*out).username = strdup(value);
                if (*out).username.is_null() {
                    return -(1 as libc::c_int);
                }
            }
            1 => {
                /* This directive is required if the server provided any
                realms in the "digest-challenge", in which case it may
                appear exactly once and its value SHOULD be one of those
                realms. */
                if !(*out).realm.is_null() {
                    return -(1 as libc::c_int);
                }
                (*out).realm = strdup(value);
                if (*out).realm.is_null() {
                    return -(1 as libc::c_int);
                }
            }
            2 => {
                /* This directive is required and MUST be present exactly
                once; otherwise, authentication fails. */
                if !(*out).nonce.is_null() {
                    return -(1 as libc::c_int);
                }
                (*out).nonce = strdup(value);
                if (*out).nonce.is_null() {
                    return -(1 as libc::c_int);
                }
            }
            3 => {
                /* This directive is required and MUST be present exactly once;
                otherwise, authentication fails. */
                if !(*out).cnonce.is_null() {
                    return -(1 as libc::c_int);
                }
                (*out).cnonce = strdup(value);
                if (*out).cnonce.is_null() {
                    return -(1 as libc::c_int);
                }
            }
            4 => {
                /* This directive is required and MUST be present exactly
                once; otherwise, authentication fails. */
                if (*out).nc != 0 {
                    return -(1 as libc::c_int);
                }
                /* nc-value = 8LHEX */
                if strlen(value) != 8 {
                    return -(1 as libc::c_int);
                }
                (*out).nc = strtoul(value, 0 as *mut *mut libc::c_char, 16 as libc::c_int) as usize
            }
            5 => {
                /* If present, it may appear exactly once and its value MUST
                be one of the alternatives in qop-options.  */
                if (*out).qop as u64 != 0 {
                    return -(1 as libc::c_int);
                }
                if strcmp(value, b"auth\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    (*out).qop = DIGEST_MD5_QOP_AUTH
                } else if strcmp(value, b"auth-int\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    (*out).qop = DIGEST_MD5_QOP_AUTH_INT
                } else if strcmp(value, b"auth-conf\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    (*out).qop = DIGEST_MD5_QOP_AUTH_CONF
                } else {
                    return -(1 as libc::c_int);
                }
            }
            6 => {
                /* This directive is required and MUST be present exactly
                once; if multiple instances are present, the client MUST
                abort the authentication exchange. */
                if !(*out).digesturi.is_null() {
                    return -(1 as libc::c_int);
                }
                /* FIXME: sub-parse. */
                (*out).digesturi = strdup(value);
                if (*out).digesturi.is_null() {
                    return -(1 as libc::c_int);
                }
            }
            7 => {
                /* This directive is required and MUST be present exactly
                once; otherwise, authentication fails. */
                if *(*out).response.as_mut_ptr() != 0 {
                    return -(1 as libc::c_int);
                }
                /* A string of 32 hex digits */
                if strlen(value) != 32 {
                    return -(1 as libc::c_int);
                }
                strcpy((*out).response.as_mut_ptr(), value);
            }
            8 => {
                /* This directive may appear at most once; if multiple
                instances are present, the server MUST abort the
                authentication exchange. */
                if (*out).clientmaxbuf != 0 {
                    return -(1 as libc::c_int);
                }
                (*out).clientmaxbuf = strtoul(value, 0 as *mut *mut libc::c_char, 10) as usize;
                /* FIXME: error handling. */
                /* If the value is less or equal to 16 (<<32 for aes-cbc>>) or
                bigger than 16777215 (i.e. 2**24-1), the server MUST abort
                the authentication exchange. */
                if (*out).clientmaxbuf <= 16 || (*out).clientmaxbuf > 16777215 {
                    return -(1 as libc::c_int);
                }
            }
            9 => {
                if strcmp(b"utf-8\x00" as *const u8 as *const libc::c_char, value)
                    != 0 as libc::c_int
                {
                    return -(1 as libc::c_int);
                }
                (*out).utf8 = 1 as libc::c_int
            }
            10 => {
                if (*out).cipher as u64 != 0 {
                    return -(1 as libc::c_int);
                }
                if strcmp(value, b"3des\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    (*out).cipher = DIGEST_MD5_CIPHER_3DES
                } else if strcmp(value, b"des\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    (*out).cipher = DIGEST_MD5_CIPHER_DES
                } else if strcmp(value, b"rc4-40\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    (*out).cipher = DIGEST_MD5_CIPHER_RC4_40
                } else if strcmp(value, b"rc4\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    (*out).cipher = DIGEST_MD5_CIPHER_RC4
                } else if strcmp(value, b"rc4-56\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    (*out).cipher = DIGEST_MD5_CIPHER_RC4_56
                } else if strcmp(value, b"aes-cbc\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    (*out).cipher = DIGEST_MD5_CIPHER_AES_CBC
                } else {
                    return -(1 as libc::c_int);
                }
            }
            11 => {
                /* This directive may appear at most once; if multiple
                instances are present, the server MUST abort the
                authentication exchange.  <<FIXME NOT IN DRAFT>> */
                if !(*out).authzid.is_null() {
                    return -(1 as libc::c_int);
                }
                /*  The authzid MUST NOT be an empty string. */
                if *value as libc::c_int == '\u{0}' as i32 {
                    return -(1 as libc::c_int);
                }
                (*out).authzid = strdup(value);
                if (*out).authzid.is_null() {
                    return -(1 as libc::c_int);
                }
            }
            _ => {}
        }
    }
    /* Validate that we have the mandatory fields. */
    if digest_md5_validate_response(out) != 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
static mut digest_responseauth_opts: [*const libc::c_char; 2] = [
    b"rspauth\x00" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
unsafe fn parse_finish(
    mut finish: *mut libc::c_char,
    out: *mut digest_md5_finish,
) -> libc::c_int {
    let mut value: *mut libc::c_char = 0 as *mut libc::c_char;
    memset(
        out as *mut libc::c_void,
        0,
        ::std::mem::size_of::<digest_md5_finish>(),
    );
    /* The size of a response-auth MUST be less than 2048 bytes. */
    if strlen(finish) >= 2048 {
        return -(1 as libc::c_int);
    }
    while *finish as libc::c_int != '\u{0}' as i32 {
        match digest_md5_getsubopt(&mut finish, digest_responseauth_opts.as_ptr(), &mut value) {
            0 => {
                if *(*out).rspauth.as_mut_ptr() != 0 {
                    return -(1 as libc::c_int);
                }
                /* A string of 32 hex digits */
                if strlen(value) != 32 {
                    return -(1 as libc::c_int);
                }
                strcpy((*out).rspauth.as_mut_ptr(), value);
            }
            _ => {}
        }
    }
    /* Validate that we have the mandatory fields. */
    if digest_md5_validate_finish(out) != 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe fn digest_md5_parse_challenge(
    challenge: *const libc::c_char,
    len: size_t,
    out: *mut digest_md5_challenge,
) -> libc::c_int {
    let subopts: *mut libc::c_char = if len != 0 {
        strndup(challenge, len)
    } else {
        strdup(challenge)
    };
    let mut rc: libc::c_int = 0;
    if subopts.is_null() {
        return -(1 as libc::c_int);
    }
    rc = parse_challenge(subopts, out);
    rpl_free(subopts as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe fn digest_md5_parse_response(
    response: *const libc::c_char,
    len: size_t,
    out: *mut digest_md5_response,
) -> libc::c_int {
    let subopts: *mut libc::c_char = if len != 0 {
        strndup(response, len)
    } else {
        strdup(response)
    };
    let mut rc: libc::c_int = 0;
    if subopts.is_null() {
        return -(1 as libc::c_int);
    }
    rc = parse_response(subopts, out);
    rpl_free(subopts as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe fn digest_md5_parse_finish(
    finish: *const libc::c_char,
    len: size_t,
    out: *mut digest_md5_finish,
) -> libc::c_int {
    let subopts: *mut libc::c_char = if len != 0 {
        strndup(finish, len)
    } else {
        strdup(finish)
    };
    let mut rc: libc::c_int = 0;
    if subopts.is_null() {
        return -(1 as libc::c_int);
    }
    rc = parse_finish(subopts, out);
    rpl_free(subopts as *mut libc::c_void);
    return rc;
}
