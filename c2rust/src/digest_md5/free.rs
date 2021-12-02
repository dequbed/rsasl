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
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
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
/* free.h --- Free allocated data in DIGEST-MD5 token structures.
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
/* free.h --- Free allocated data in DIGEST-MD5 token structures.
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
/* Get memset. */
#[no_mangle]
pub unsafe extern "C" fn digest_md5_free_challenge(mut c:
                                                       *mut digest_md5_challenge) {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < (*c).nrealms {
        rpl_free(*(*c).realms.offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1)
    }
    rpl_free((*c).realms as *mut libc::c_void);
    rpl_free((*c).nonce as *mut libc::c_void);
    memset(c as *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<digest_md5_challenge>() as libc::c_ulong);
}
#[no_mangle]
pub unsafe extern "C" fn digest_md5_free_response(mut r:
                                                      *mut digest_md5_response) {
    rpl_free((*r).username as *mut libc::c_void);
    rpl_free((*r).realm as *mut libc::c_void);
    rpl_free((*r).nonce as *mut libc::c_void);
    rpl_free((*r).cnonce as *mut libc::c_void);
    rpl_free((*r).digesturi as *mut libc::c_void);
    rpl_free((*r).authzid as *mut libc::c_void);
    memset(r as *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<digest_md5_response>() as libc::c_ulong);
}
#[no_mangle]
pub unsafe extern "C" fn digest_md5_free_finish(mut f:
                                                    *mut digest_md5_finish) {
    memset(f as *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<digest_md5_finish>() as libc::c_ulong);
}
