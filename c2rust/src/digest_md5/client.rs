use ::libc;
use libc::size_t;
use crate::base64::gsasl_base64_to;
use crate::callback::gsasl_callback;
use crate::consts::{GSASL_AUTHENTICATION_ERROR, GSASL_AUTHID, GSASL_AUTHZID, GSASL_CRYPTO_ERROR, GSASL_HOSTNAME, GSASL_INTEGRITY_ERROR, GSASL_MALLOC_ERROR, GSASL_MECHANISM_CALLED_TOO_MANY_TIMES, GSASL_MECHANISM_PARSE_ERROR, GSASL_NEEDS_MORE, GSASL_NO_AUTHID, GSASL_NO_HOSTNAME, GSASL_NO_PASSWORD, GSASL_NO_SERVICE, GSASL_OK, GSASL_PASSWORD, GSASL_QOP, GSASL_QOPS, GSASL_REALM, GSASL_SERVICE};
use crate::crypto::gsasl_nonce;
use crate::gc::{GC_OK, Gc_rc};
use crate::gsasl::{Gsasl, Gsasl_session};
use crate::property::{gsasl_property_fast, gsasl_property_get, gsasl_property_set};

extern "C" {
    #[no_mangle]
    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char,
                _: ...) -> libc::c_int;
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
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> size_t;
    #[no_mangle]
    fn gc_md5(in_0: *const libc::c_void, inlen: size_t,
              resbuf: *mut libc::c_void) -> Gc_rc;
    #[no_mangle]
    fn utf8tolatin1ifpossible(passwd: *const libc::c_char)
     -> *mut libc::c_char;
    #[no_mangle]
    fn digest_md5_parse_challenge(challenge: *const libc::c_char, len: size_t,
                                  out: *mut digest_md5_challenge)
     -> libc::c_int;
    #[no_mangle]
    fn digest_md5_parse_finish(finish: *const libc::c_char, len: size_t,
                               out: *mut digest_md5_finish) -> libc::c_int;
    #[no_mangle]
    fn digest_md5_print_response(response: *mut digest_md5_response)
     -> *mut libc::c_char;
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
    #[no_mangle]
    fn digest_md5_free_challenge(c: *mut digest_md5_challenge);
    #[no_mangle]
    fn digest_md5_free_response(r: *mut digest_md5_response);
    #[no_mangle]
    fn digest_md5_free_finish(f: *mut digest_md5_finish);
    /* session.h --- Data integrity/privacy protection of DIGEST-MD5.
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
    /* Get token types. */
    #[no_mangle]
    fn digest_md5_encode(input: *const libc::c_char, input_len: size_t,
                         output: *mut *mut libc::c_char,
                         output_len: *mut size_t, qop: digest_md5_qop,
                         sendseqnum: libc::c_ulong, key: *mut libc::c_char)
     -> libc::c_int;
    #[no_mangle]
    fn digest_md5_decode(input: *const libc::c_char, input_len: size_t,
                         output: *mut *mut libc::c_char,
                         output_len: *mut size_t, qop: digest_md5_qop,
                         readseqnum: libc::c_ulong, key: *mut libc::c_char)
     -> libc::c_int;
    /* digesthmac.h --- Compute DIGEST-MD5 response value.
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
    /* Compute in 33 bytes large array OUTPUT the DIGEST-MD5 response
   value.  SECRET holds the 16 bytes MD5 hash SS, i.e.,
   H(username:realm:passwd).  NONCE is a zero terminated string with
   the server nonce.  NC is the nonce-count, typically 1 for initial
   authentication.  CNONCE is a zero terminated string with the client
   nonce.  QOP is the quality of protection to use.  AUTHZID is a zero
   terminated string with the authorization identity.  DIGESTURI is a
   zero terminated string with the server principal (e.g.,
   imap/mail.example.org).  RSPAUTH is a boolean which indicate
   whether to compute a value for the RSPAUTH response or the "real"
   authentication.  CIPHER is the cipher to use.  KIC, KIS, KCC, KCS
   are either NULL, or points to 16 byte arrays that will hold the
   computed keys on output.  Returns 0 on success. */
    #[no_mangle]
    fn digest_md5_hmac(output: *mut libc::c_char, secret: *mut libc::c_char,
                       nonce: *const libc::c_char, nc: libc::c_ulong,
                       cnonce: *const libc::c_char, qop: digest_md5_qop,
                       authzid: *const libc::c_char,
                       digesturi: *const libc::c_char, rspauth: libc::c_int,
                       cipher: digest_md5_cipher, kic: *mut libc::c_char,
                       kis: *mut libc::c_char, kcc: *mut libc::c_char,
                       kcs: *mut libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn digest_md5_qops2qopstr(qops: libc::c_int) -> *const libc::c_char;
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _Gsasl_digest_md5_client_state {
    pub step: libc::c_int,
    pub readseqnum: libc::c_ulong,
    pub sendseqnum: libc::c_ulong,
    pub secret: [libc::c_char; 16],
    pub kic: [libc::c_char; 16],
    pub kcc: [libc::c_char; 16],
    pub kis: [libc::c_char; 16],
    pub kcs: [libc::c_char; 16],
    pub challenge: digest_md5_challenge,
    pub response: digest_md5_response,
    pub finish: digest_md5_finish,
}
/*
 * response-auth = "rspauth" "=" response-value
 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct digest_md5_finish {
    pub rspauth: [libc::c_char; 33],
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
/* Cipher types. */
pub type digest_md5_cipher = libc::c_uint;
pub const DIGEST_MD5_CIPHER_AES_CBC: digest_md5_cipher = 32;
pub const DIGEST_MD5_CIPHER_RC4_56: digest_md5_cipher = 16;
pub const DIGEST_MD5_CIPHER_RC4_40: digest_md5_cipher = 8;
pub const DIGEST_MD5_CIPHER_RC4: digest_md5_cipher = 4;
pub const DIGEST_MD5_CIPHER_3DES: digest_md5_cipher = 2;
pub const DIGEST_MD5_CIPHER_DES: digest_md5_cipher = 1;
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
/* gc.h --- Header file for implementation agnostic crypto wrapper API.
 * Copyright (C) 2002-2005, 2007-2008, 2011-2021 Free Software Foundation, Inc.
 *
 * This file is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */
#[no_mangle]
pub unsafe extern "C" fn _gsasl_digest_md5_client_start(mut sctx:
                                                            *mut Gsasl_session,
                                                        mut mech_data:
                                                            *mut *mut libc::c_void)
 -> libc::c_int {
    let mut state: *mut _Gsasl_digest_md5_client_state =
        0 as *mut _Gsasl_digest_md5_client_state;
    let mut nonce: [libc::c_char; 16] = [0; 16];
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut rc: libc::c_int = 0;
    rc = gsasl_nonce(nonce.as_mut_ptr(), 16 as libc::c_int as size_t);
    if rc != GSASL_OK as libc::c_int { return rc }
    rc =
        gsasl_base64_to(nonce.as_mut_ptr(), 16 as libc::c_int as size_t,
                        &mut p, 0 as *mut size_t);
    if rc != GSASL_OK as libc::c_int { return rc }
    state =
        calloc(1, ::std::mem::size_of::<_Gsasl_digest_md5_client_state>())
            as *mut _Gsasl_digest_md5_client_state;
    if state.is_null() {
        rpl_free(p as *mut libc::c_void);
        return GSASL_MALLOC_ERROR as libc::c_int
    }
    (*state).response.cnonce = p;
    (*state).response.nc = 1 as libc::c_int as libc::c_ulong;
    *mech_data = state as *mut libc::c_void;
    return GSASL_OK as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn _gsasl_digest_md5_client_step(mut sctx: *mut Gsasl_session,
                                                       mut mech_data: *mut libc::c_void,
                                                       mut input: *const libc::c_char,
                                                       mut input_len: size_t,
                                                       mut output: *mut *mut libc::c_char,
                                                       mut output_len: *mut size_t
    ) -> libc::c_int
{
    let mut state: *mut _Gsasl_digest_md5_client_state =
        mech_data as *mut _Gsasl_digest_md5_client_state;
    let mut rc: libc::c_int = 0;
    let mut res: libc::c_int = 0;
    *output = 0 as *mut libc::c_char;
    *output_len = 0 as libc::c_int as size_t;
    if (*state).step == 0 as libc::c_int {
        (*state).step += 1;
        if input_len == 0 {
            return GSASL_NEEDS_MORE as libc::c_int
        }
    }
    match (*state).step {
        1 => {
            if digest_md5_parse_challenge(input, input_len,
                                          &mut (*state).challenge) <
                   0 as libc::c_int {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            /* FIXME: How to let application know of remaining realms?
	   One idea, add a GSASL_REALM_COUNT property, and have the
	   GSASL_REALM be that many concatenated zero terminated realm
	   strings.  Slightly hackish, though.  Another cleaner
	   approach would be to add gsasl_property_set_array and
	   gsasl_property_get_array APIs, for those properties that
	   may be used multiple times. */
            if (*state).challenge.nrealms > 0
               {
                res =
                    gsasl_property_set(sctx, GSASL_REALM,
                                       *(*state).challenge.realms.offset(0 as
                                                                             libc::c_int
                                                                             as
                                                                             isize))
            } else {
                res =
                    gsasl_property_set(sctx, GSASL_REALM,
                                       0 as *const libc::c_char)
            }
            if res != GSASL_OK as libc::c_int { return res }
            /* FIXME: cipher, maxbuf. */
            /* Create response token. */
            (*state).response.utf8 = 1 as libc::c_int;
            res =
                gsasl_property_set(sctx, GSASL_QOPS,
                                   digest_md5_qops2qopstr((*state).challenge.qops));
            if res != GSASL_OK as libc::c_int { return res }
            let mut qop: *const libc::c_char =
                gsasl_property_get(sctx, GSASL_QOP);
            if qop.is_null() {
                (*state).response.qop = DIGEST_MD5_QOP_AUTH
            } else if strcmp(qop,
                             b"qop-int\x00" as *const u8 as
                                 *const libc::c_char) == 0 as libc::c_int {
                (*state).response.qop = DIGEST_MD5_QOP_AUTH_INT
            } else if strcmp(qop,
                             b"qop-auth\x00" as *const u8 as
                                 *const libc::c_char) == 0 as libc::c_int {
                (*state).response.qop = DIGEST_MD5_QOP_AUTH
            } else {
                /* We don't support confidentiality or unknown
	       keywords. */
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            (*state).response.nonce = strdup((*state).challenge.nonce);
            if (*state).response.nonce.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            let mut service: *const libc::c_char =
                gsasl_property_get(sctx, GSASL_SERVICE);
            let mut hostname: *const libc::c_char =
                gsasl_property_get(sctx, GSASL_HOSTNAME);
            if service.is_null() { return GSASL_NO_SERVICE as libc::c_int }
            if hostname.is_null() { return GSASL_NO_HOSTNAME as libc::c_int }
            if asprintf(&mut (*state).response.digesturi as
                            *mut *mut libc::c_char,
                        b"%s/%s\x00" as *const u8 as *const libc::c_char,
                        service, hostname) < 0 as libc::c_int {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            let mut c: *const libc::c_char = 0 as *const libc::c_char;
            let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut tmp2: *mut libc::c_char = 0 as *mut libc::c_char;
            c = gsasl_property_get(sctx, GSASL_AUTHID);
            if c.is_null() { return GSASL_NO_AUTHID as libc::c_int }
            (*state).response.username = strdup(c);
            if (*state).response.username.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            c = gsasl_property_get(sctx, GSASL_AUTHZID);
            if !c.is_null() {
                (*state).response.authzid = strdup(c);
                if (*state).response.authzid.is_null() {
                    return GSASL_MALLOC_ERROR as libc::c_int
                }
            }
            gsasl_callback(0 as *mut Gsasl, sctx, GSASL_REALM);
            c = gsasl_property_fast(sctx, GSASL_REALM);
            if !c.is_null() {
                (*state).response.realm = strdup(c);
                if (*state).response.realm.is_null() {
                    return GSASL_MALLOC_ERROR as libc::c_int
                }
            }
            c = gsasl_property_get(sctx, GSASL_PASSWORD);
            if c.is_null() { return GSASL_NO_PASSWORD as libc::c_int }
            tmp2 = utf8tolatin1ifpossible(c);
            rc =
                asprintf(&mut tmp as *mut *mut libc::c_char,
                         b"%s:%s:%s\x00" as *const u8 as *const libc::c_char,
                         (*state).response.username,
                         if !(*state).response.realm.is_null() {
                             (*state).response.realm
                         } else {
                             b"\x00" as *const u8 as *const libc::c_char
                         }, tmp2);
            rpl_free(tmp2 as *mut libc::c_void);
            if rc < 0 as libc::c_int {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            rc =
                gc_md5(tmp as *const libc::c_void, strlen(tmp),
                       (*state).secret.as_mut_ptr() as *mut libc::c_void) as
                    libc::c_int;
            rpl_free(tmp as *mut libc::c_void);
            if rc != GC_OK as libc::c_int {
                return GSASL_CRYPTO_ERROR as libc::c_int
            }
            rc =
                digest_md5_hmac((*state).response.response.as_mut_ptr(),
                                (*state).secret.as_mut_ptr(),
                                (*state).response.nonce, (*state).response.nc,
                                (*state).response.cnonce,
                                (*state).response.qop,
                                (*state).response.authzid,
                                (*state).response.digesturi, 0 as libc::c_int,
                                (*state).response.cipher,
                                (*state).kic.as_mut_ptr(),
                                (*state).kis.as_mut_ptr(),
                                (*state).kcc.as_mut_ptr(),
                                (*state).kcs.as_mut_ptr());
            if rc != 0 { return GSASL_CRYPTO_ERROR as libc::c_int }
            *output = digest_md5_print_response(&mut (*state).response);
            if (*output).is_null() {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            *output_len = strlen(*output);
            (*state).step += 1;
            res = GSASL_NEEDS_MORE as libc::c_int
        }
        2 => {
            let mut check: [libc::c_char; 33] = [0; 33];
            if digest_md5_parse_finish(input, input_len, &mut (*state).finish)
                   < 0 as libc::c_int {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            res =
                digest_md5_hmac(check.as_mut_ptr(),
                                (*state).secret.as_mut_ptr(),
                                (*state).response.nonce, (*state).response.nc,
                                (*state).response.cnonce,
                                (*state).response.qop,
                                (*state).response.authzid,
                                (*state).response.digesturi, 1 as libc::c_int,
                                (*state).response.cipher,
                                0 as *mut libc::c_char,
                                0 as *mut libc::c_char,
                                0 as *mut libc::c_char,
                                0 as *mut libc::c_char);
            if !(res != GSASL_OK as libc::c_int) {
                if strcmp((*state).finish.rspauth.as_mut_ptr(),
                          check.as_mut_ptr()) == 0 as libc::c_int {
                    res = GSASL_OK as libc::c_int
                } else { res = GSASL_AUTHENTICATION_ERROR as libc::c_int }
                (*state).step += 1
            }
        }
        _ => { res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int }
    }
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn _gsasl_digest_md5_client_finish(mut sctx: *mut Gsasl_session,
                                                         mut mech_data: *mut libc::c_void
)
{
    let mut state: *mut _Gsasl_digest_md5_client_state =
        mech_data as *mut _Gsasl_digest_md5_client_state;
    if state.is_null() { return }
    digest_md5_free_challenge(&mut (*state).challenge);
    digest_md5_free_response(&mut (*state).response);
    digest_md5_free_finish(&mut (*state).finish);
    rpl_free(state as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn _gsasl_digest_md5_client_encode(mut sctx: *mut Gsasl_session,
                                                         mut mech_data: *mut libc::c_void,
                                                         mut input: *const libc::c_char,
                                                         mut input_len: size_t,
                                                         mut output: *mut *mut libc::c_char,
                                                         mut output_len: *mut size_t
    ) -> libc::c_int
{
    let mut state: *mut _Gsasl_digest_md5_client_state =
        mech_data as *mut _Gsasl_digest_md5_client_state;
    let mut res: libc::c_int = 0;
    res =
        digest_md5_encode(input, input_len, output, output_len,
                          (*state).response.qop, (*state).sendseqnum,
                          (*state).kic.as_mut_ptr());
    if res != 0 {
        return if res == -(2 as libc::c_int) {
                   GSASL_NEEDS_MORE as libc::c_int
               } else { GSASL_INTEGRITY_ERROR as libc::c_int }
    }
    if (*state).sendseqnum == 4294967295 as libc::c_ulong {
        (*state).sendseqnum = 0 as libc::c_int as libc::c_ulong
    } else { (*state).sendseqnum = (*state).sendseqnum.wrapping_add(1) }
    return GSASL_OK as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn _gsasl_digest_md5_client_decode(mut sctx: *mut Gsasl_session,
                                                         mut mech_data: *mut libc::c_void,
                                                         mut input: *const libc::c_char,
                                                         mut input_len: size_t,
                                                         mut output: *mut *mut libc::c_char,
                                                         mut output_len: *mut size_t
    ) -> libc::c_int
{
    let mut state: *mut _Gsasl_digest_md5_client_state =
        mech_data as *mut _Gsasl_digest_md5_client_state;
    let mut res: libc::c_int = 0;
    res =
        digest_md5_decode(input, input_len, output, output_len,
                          (*state).response.qop, (*state).readseqnum,
                          (*state).kis.as_mut_ptr());
    if res != 0 {
        return if res == -(2 as libc::c_int) {
                   GSASL_NEEDS_MORE as libc::c_int
               } else { GSASL_INTEGRITY_ERROR as libc::c_int }
    }
    if (*state).readseqnum == 4294967295 as libc::c_ulong {
        (*state).readseqnum = 0 as libc::c_int as libc::c_ulong
    } else { (*state).readseqnum = (*state).readseqnum.wrapping_add(1) }
    return GSASL_OK as libc::c_int;
}
