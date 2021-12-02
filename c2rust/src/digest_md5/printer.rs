use ::libc;
extern "C" {
    /* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* A GNU-like <stdlib.h>.

   Copyright (C) 1995, 2001-2004, 2006-2021 Free Software Foundation, Inc.

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
    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char,
                _: ...) -> libc::c_int;
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
    fn digest_md5_validate_challenge(c: *mut digest_md5_challenge)
     -> libc::c_int;
    #[no_mangle]
    fn digest_md5_validate_response(r: *mut digest_md5_response)
     -> libc::c_int;
    #[no_mangle]
    fn digest_md5_validate_finish(f: *mut digest_md5_finish) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
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
    pub servermaxbuf: libc::c_ulong,
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
    pub nc: libc::c_ulong,
    pub qop: digest_md5_qop,
    pub digesturi: *mut libc::c_char,
    pub clientmaxbuf: libc::c_ulong,
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
/* printer.h --- Convert DIGEST-MD5 token structures into strings.
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
/* Get free. */
/* Get asprintf. */
/* Get token validator. */
/* Append a key/value pair to a comma'd string list.  Additionally enclose
   the value in quotes if requested. */
unsafe extern "C" fn comma_append(mut dst: *mut *mut libc::c_char,
                                  mut key: *const libc::c_char,
                                  mut value: *const libc::c_char,
                                  mut quotes: libc::c_int) -> libc::c_int {
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut result: libc::c_int = 0;
    if !(*dst).is_null() {
        if !value.is_null() {
            if quotes != 0 {
                result =
                    asprintf(&mut tmp as *mut *mut libc::c_char,
                             b"%s, %s=\"%s\"\x00" as *const u8 as
                                 *const libc::c_char, *dst, key, value)
            } else {
                result =
                    asprintf(&mut tmp as *mut *mut libc::c_char,
                             b"%s, %s=%s\x00" as *const u8 as
                                 *const libc::c_char, *dst, key, value)
            }
        } else {
            result =
                asprintf(&mut tmp as *mut *mut libc::c_char,
                         b"%s, %s\x00" as *const u8 as *const libc::c_char,
                         *dst, key)
        }
    } else if !value.is_null() {
        if quotes != 0 {
            result =
                asprintf(&mut tmp as *mut *mut libc::c_char,
                         b"%s=\"%s\"\x00" as *const u8 as *const libc::c_char,
                         key, value)
        } else {
            result =
                asprintf(&mut tmp as *mut *mut libc::c_char,
                         b"%s=%s\x00" as *const u8 as *const libc::c_char,
                         key, value)
        }
    } else {
        result =
            asprintf(&mut tmp as *mut *mut libc::c_char,
                     b"%s\x00" as *const u8 as *const libc::c_char, key)
    }
    if result < 0 as libc::c_int { return result }
    rpl_free(*dst as *mut libc::c_void);
    *dst = tmp;
    return result;
}
/* printer.h --- Convert DIGEST-MD5 token structures into strings.
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
pub unsafe extern "C" fn digest_md5_print_challenge(mut c:
                                                        *mut digest_md5_challenge)
 -> *mut libc::c_char {
    let mut out: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: size_t = 0;
    /* Below we assume the mandatory fields are present, verify that
     first to avoid crashes. */
    if digest_md5_validate_challenge(c) != 0 as libc::c_int {
        return 0 as *mut libc::c_char
    }
    i = 0 as libc::c_int as size_t;
    while i < (*c).nrealms {
        if comma_append(&mut out,
                        b"realm\x00" as *const u8 as *const libc::c_char,
                        *(*c).realms.offset(i as isize), 1 as libc::c_int) <
               0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
        i = i.wrapping_add(1)
    }
    if !(*c).nonce.is_null() {
        if comma_append(&mut out,
                        b"nonce\x00" as *const u8 as *const libc::c_char,
                        (*c).nonce, 1 as libc::c_int) < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
    }
    if (*c).qops != 0 {
        let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
        if (*c).qops & DIGEST_MD5_QOP_AUTH as libc::c_int != 0 {
            if comma_append(&mut tmp,
                            b"auth\x00" as *const u8 as *const libc::c_char,
                            0 as *const libc::c_char, 0 as libc::c_int) <
                   0 as libc::c_int {
                rpl_free(tmp as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char
            }
        }
        if (*c).qops & DIGEST_MD5_QOP_AUTH_INT as libc::c_int != 0 {
            if comma_append(&mut tmp,
                            b"auth-int\x00" as *const u8 as
                                *const libc::c_char, 0 as *const libc::c_char,
                            0 as libc::c_int) < 0 as libc::c_int {
                rpl_free(tmp as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char
            }
        }
        if (*c).qops & DIGEST_MD5_QOP_AUTH_CONF as libc::c_int != 0 {
            if comma_append(&mut tmp,
                            b"auth-conf\x00" as *const u8 as
                                *const libc::c_char, 0 as *const libc::c_char,
                            0 as libc::c_int) < 0 as libc::c_int {
                rpl_free(tmp as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char
            }
        }
        if comma_append(&mut out,
                        b"qop\x00" as *const u8 as *const libc::c_char, tmp,
                        1 as libc::c_int) < 0 as libc::c_int {
            rpl_free(tmp as *mut libc::c_void);
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
        rpl_free(tmp as *mut libc::c_void);
    }
    if (*c).stale != 0 {
        if comma_append(&mut out,
                        b"stale\x00" as *const u8 as *const libc::c_char,
                        b"true\x00" as *const u8 as *const libc::c_char,
                        0 as libc::c_int) < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
    }
    if (*c).servermaxbuf != 0 {
        let mut tmp_0: *mut libc::c_char = 0 as *mut libc::c_char;
        if asprintf(&mut tmp_0 as *mut *mut libc::c_char,
                    b"%lu\x00" as *const u8 as *const libc::c_char,
                    (*c).servermaxbuf) < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
        if comma_append(&mut out,
                        b"maxbuf\x00" as *const u8 as *const libc::c_char,
                        tmp_0, 0 as libc::c_int) < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
        rpl_free(tmp_0 as *mut libc::c_void);
    }
    if (*c).utf8 != 0 {
        if comma_append(&mut out,
                        b"charset\x00" as *const u8 as *const libc::c_char,
                        b"utf-8\x00" as *const u8 as *const libc::c_char,
                        0 as libc::c_int) < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
    }
    if comma_append(&mut out,
                    b"algorithm\x00" as *const u8 as *const libc::c_char,
                    b"md5-sess\x00" as *const u8 as *const libc::c_char,
                    0 as libc::c_int) < 0 as libc::c_int {
        rpl_free(out as *mut libc::c_void);
        return 0 as *mut libc::c_char
    }
    if (*c).ciphers != 0 {
        let mut tmp_1: *mut libc::c_char = 0 as *mut libc::c_char;
        if (*c).ciphers & DIGEST_MD5_CIPHER_3DES as libc::c_int != 0 {
            if comma_append(&mut tmp_1,
                            b"3des\x00" as *const u8 as *const libc::c_char,
                            0 as *const libc::c_char, 0 as libc::c_int) <
                   0 as libc::c_int {
                rpl_free(tmp_1 as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char
            }
        }
        if (*c).ciphers & DIGEST_MD5_CIPHER_DES as libc::c_int != 0 {
            if comma_append(&mut tmp_1,
                            b"des\x00" as *const u8 as *const libc::c_char,
                            0 as *const libc::c_char, 0 as libc::c_int) <
                   0 as libc::c_int {
                rpl_free(tmp_1 as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char
            }
        }
        if (*c).ciphers & DIGEST_MD5_CIPHER_RC4_40 as libc::c_int != 0 {
            if comma_append(&mut tmp_1,
                            b"rc4-40\x00" as *const u8 as *const libc::c_char,
                            0 as *const libc::c_char, 0 as libc::c_int) <
                   0 as libc::c_int {
                rpl_free(tmp_1 as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char
            }
        }
        if (*c).ciphers & DIGEST_MD5_CIPHER_RC4 as libc::c_int != 0 {
            if comma_append(&mut tmp_1,
                            b"rc4\x00" as *const u8 as *const libc::c_char,
                            0 as *const libc::c_char, 0 as libc::c_int) <
                   0 as libc::c_int {
                rpl_free(tmp_1 as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char
            }
        }
        if (*c).ciphers & DIGEST_MD5_CIPHER_RC4_56 as libc::c_int != 0 {
            if comma_append(&mut tmp_1,
                            b"rc4-56\x00" as *const u8 as *const libc::c_char,
                            0 as *const libc::c_char, 0 as libc::c_int) <
                   0 as libc::c_int {
                rpl_free(tmp_1 as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char
            }
        }
        if (*c).ciphers & DIGEST_MD5_CIPHER_AES_CBC as libc::c_int != 0 {
            if comma_append(&mut tmp_1,
                            b"aes-cbc\x00" as *const u8 as
                                *const libc::c_char, 0 as *const libc::c_char,
                            0 as libc::c_int) < 0 as libc::c_int {
                rpl_free(tmp_1 as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char
            }
        }
        if comma_append(&mut out,
                        b"cipher\x00" as *const u8 as *const libc::c_char,
                        tmp_1, 1 as libc::c_int) < 0 as libc::c_int {
            rpl_free(tmp_1 as *mut libc::c_void);
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
        rpl_free(tmp_1 as *mut libc::c_void);
    }
    return out;
}
#[no_mangle]
pub unsafe extern "C" fn digest_md5_print_response(mut r:
                                                       *mut digest_md5_response)
 -> *mut libc::c_char {
    let mut out: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut qop: *const libc::c_char = 0 as *const libc::c_char;
    let mut cipher: *const libc::c_char = 0 as *const libc::c_char;
    /* Below we assume the mandatory fields are present, verify that
     first to avoid crashes. */
    if digest_md5_validate_response(r) != 0 as libc::c_int {
        return 0 as *mut libc::c_char
    }
    if (*r).qop as libc::c_uint &
           DIGEST_MD5_QOP_AUTH_CONF as libc::c_int as libc::c_uint != 0 {
        qop = b"qop=auth-conf\x00" as *const u8 as *const libc::c_char
    } else if (*r).qop as libc::c_uint &
                  DIGEST_MD5_QOP_AUTH_INT as libc::c_int as libc::c_uint != 0
     {
        qop = b"qop=auth-int\x00" as *const u8 as *const libc::c_char
    } else if (*r).qop as libc::c_uint &
                  DIGEST_MD5_QOP_AUTH as libc::c_int as libc::c_uint != 0 {
        qop = b"qop=auth\x00" as *const u8 as *const libc::c_char
    }
    if (*r).cipher as libc::c_uint &
           DIGEST_MD5_CIPHER_3DES as libc::c_int as libc::c_uint != 0 {
        cipher = b"cipher=3des\x00" as *const u8 as *const libc::c_char
    } else if (*r).cipher as libc::c_uint &
                  DIGEST_MD5_CIPHER_DES as libc::c_int as libc::c_uint != 0 {
        cipher = b"cipher=des\x00" as *const u8 as *const libc::c_char
    } else if (*r).cipher as libc::c_uint &
                  DIGEST_MD5_CIPHER_RC4_40 as libc::c_int as libc::c_uint != 0
     {
        cipher = b"cipher=rc4-40\x00" as *const u8 as *const libc::c_char
    } else if (*r).cipher as libc::c_uint &
                  DIGEST_MD5_CIPHER_RC4 as libc::c_int as libc::c_uint != 0 {
        cipher = b"cipher=rc4\x00" as *const u8 as *const libc::c_char
    } else if (*r).cipher as libc::c_uint &
                  DIGEST_MD5_CIPHER_RC4_56 as libc::c_int as libc::c_uint != 0
     {
        cipher = b"cipher=rc4-56\x00" as *const u8 as *const libc::c_char
    } else if (*r).cipher as libc::c_uint &
                  DIGEST_MD5_CIPHER_AES_CBC as libc::c_int as libc::c_uint !=
                  0 {
        cipher = b"cipher=aes-cbc\x00" as *const u8 as *const libc::c_char
    }
    if !(*r).username.is_null() {
        if comma_append(&mut out,
                        b"username\x00" as *const u8 as *const libc::c_char,
                        (*r).username, 1 as libc::c_int) < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
    }
    if !(*r).realm.is_null() {
        if comma_append(&mut out,
                        b"realm\x00" as *const u8 as *const libc::c_char,
                        (*r).realm, 1 as libc::c_int) < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
    }
    if !(*r).nonce.is_null() {
        if comma_append(&mut out,
                        b"nonce\x00" as *const u8 as *const libc::c_char,
                        (*r).nonce, 1 as libc::c_int) < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
    }
    if !(*r).cnonce.is_null() {
        if comma_append(&mut out,
                        b"cnonce\x00" as *const u8 as *const libc::c_char,
                        (*r).cnonce, 1 as libc::c_int) < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
    }
    if (*r).nc != 0 {
        let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
        if asprintf(&mut tmp as *mut *mut libc::c_char,
                    b"%08lx\x00" as *const u8 as *const libc::c_char, (*r).nc)
               < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
        if comma_append(&mut out,
                        b"nc\x00" as *const u8 as *const libc::c_char, tmp,
                        0 as libc::c_int) < 0 as libc::c_int {
            rpl_free(tmp as *mut libc::c_void);
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
        rpl_free(tmp as *mut libc::c_void);
    }
    if !qop.is_null() {
        if comma_append(&mut out, qop, 0 as *const libc::c_char,
                        0 as libc::c_int) < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
    }
    if !(*r).digesturi.is_null() {
        if comma_append(&mut out,
                        b"digest-uri\x00" as *const u8 as *const libc::c_char,
                        (*r).digesturi, 1 as libc::c_int) < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
    }
    if !(*r).response.as_mut_ptr().is_null() {
        if comma_append(&mut out,
                        b"response\x00" as *const u8 as *const libc::c_char,
                        (*r).response.as_mut_ptr(), 0 as libc::c_int) <
               0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
    }
    if (*r).clientmaxbuf != 0 {
        let mut tmp_0: *mut libc::c_char = 0 as *mut libc::c_char;
        if asprintf(&mut tmp_0 as *mut *mut libc::c_char,
                    b"%lu\x00" as *const u8 as *const libc::c_char,
                    (*r).clientmaxbuf) < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
        if comma_append(&mut out,
                        b"maxbuf\x00" as *const u8 as *const libc::c_char,
                        tmp_0, 0 as libc::c_int) < 0 as libc::c_int {
            rpl_free(tmp_0 as *mut libc::c_void);
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
        rpl_free(tmp_0 as *mut libc::c_void);
    }
    if (*r).utf8 != 0 {
        if comma_append(&mut out,
                        b"charset\x00" as *const u8 as *const libc::c_char,
                        b"utf-8\x00" as *const u8 as *const libc::c_char,
                        0 as libc::c_int) < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
    }
    if !cipher.is_null() {
        if comma_append(&mut out, cipher, 0 as *const libc::c_char,
                        0 as libc::c_int) < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
    }
    if !(*r).authzid.is_null() {
        if comma_append(&mut out,
                        b"authzid\x00" as *const u8 as *const libc::c_char,
                        (*r).authzid, 1 as libc::c_int) < 0 as libc::c_int {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char
        }
    }
    return out;
}
#[no_mangle]
pub unsafe extern "C" fn digest_md5_print_finish(mut finish:
                                                     *mut digest_md5_finish)
 -> *mut libc::c_char {
    let mut out: *mut libc::c_char = 0 as *mut libc::c_char;
    /* Below we assume the mandatory fields are present, verify that
     first to avoid crashes. */
    if digest_md5_validate_finish(finish) != 0 as libc::c_int {
        return 0 as *mut libc::c_char
    }
    if asprintf(&mut out as *mut *mut libc::c_char,
                b"rspauth=%s\x00" as *const u8 as *const libc::c_char,
                (*finish).rspauth.as_mut_ptr()) < 0 as libc::c_int {
        return 0 as *mut libc::c_char
    }
    return out;
}
