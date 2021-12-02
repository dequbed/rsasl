use ::libc;
use crate::gsasl::Gsasl_session;

extern "C" {
    /* Callback handling: callback.c */
    /* Property handling: property.c */
    #[no_mangle]
    fn gsasl_property_get(sctx: *mut Gsasl_session, prop: Gsasl_property)
     -> *const libc::c_char;
    #[no_mangle]
    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char,
                _: ...) -> libc::c_int;
    #[no_mangle]
    fn gsasl_property_set(sctx: *mut Gsasl_session, prop: Gsasl_property,
                          data: *const libc::c_char) -> libc::c_int;
    /* Authentication functions: xstart.c, xstep.c, xfinish.c */
    /* Session functions: xcode.c, mechname.c */
    /* Error handling: error.c */
    /* Internationalized string processing: stringprep.c */
    /* Crypto functions: crypto.c */
    /* *
   * Gsasl_hash:
   * @GSASL_HASH_SHA1: Hash function SHA-1.
   * @GSASL_HASH_SHA256: Hash function SHA-256.
   *
   * Hash functions.  You may use gsasl_hash_length() to get the
   * output size of a hash function.
   *
   * Currently only used as parameter to
   * gsasl_scram_secrets_from_salted_password() and
   * gsasl_scram_secrets_from_password() to specify for which SCRAM
   * mechanism to prepare secrets for.
   *
   * Since: 1.10
   */
    /* Hash algorithm identifiers. */
    /* *
   * Gsasl_hash_length:
   * @GSASL_HASH_SHA1_SIZE: Output size of hash function SHA-1.
   * @GSASL_HASH_SHA256_SIZE: Output size of hash function SHA-256.
   * @GSASL_HASH_MAX_SIZE: Maximum output size of any %Gsasl_hash_length.
   *
   * Identifiers specifying the output size of hash functions.
   *
   * These can be used when statically allocating the buffers needed
   * for, e.g., gsasl_scram_secrets_from_password().
   *
   * Since: 1.10
   */
    /* Output sizes of hashes. */
    /* Utilities: md5pwd.c, base64.c, free.c */
    #[no_mangle]
    fn gsasl_free(ptr: *mut libc::c_void);
    #[no_mangle]
    fn gsasl_saslprep(in_0: *const libc::c_char, flags: Gsasl_saslprep_flags,
                      out: *mut *mut libc::c_char,
                      stringpreprc: *mut libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn gsasl_nonce(data: *mut libc::c_char, datalen: size_t) -> libc::c_int;
    #[no_mangle]
    fn gsasl_hash_length(hash: Gsasl_hash) -> size_t;
    #[no_mangle]
    fn gsasl_scram_secrets_from_password(hash: Gsasl_hash,
                                         password: *const libc::c_char,
                                         iteration_count: libc::c_uint,
                                         salt: *const libc::c_char,
                                         saltlen: size_t,
                                         salted_password: *mut libc::c_char,
                                         client_key: *mut libc::c_char,
                                         server_key: *mut libc::c_char,
                                         stored_key: *mut libc::c_char)
     -> libc::c_int;
    #[no_mangle]
    fn gsasl_base64_to(in_0: *const libc::c_char, inlen: size_t,
                       out: *mut *mut libc::c_char, outlen: *mut size_t)
     -> libc::c_int;
    #[no_mangle]
    fn gsasl_base64_from(in_0: *const libc::c_char, inlen: size_t,
                         out: *mut *mut libc::c_char, outlen: *mut size_t)
     -> libc::c_int;
    #[no_mangle]
    fn strtoul(_: *const libc::c_char, _: *mut *mut libc::c_char,
               _: libc::c_int) -> libc::c_ulong;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
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
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void,
              _: libc::c_ulong) -> libc::c_int;
    #[no_mangle]
    fn memchr(_: *const libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    #[no_mangle]
    fn memmem(__haystack: *const libc::c_void, __haystacklen: size_t,
              __needle: *const libc::c_void, __needlelen: size_t)
     -> *mut libc::c_void;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    #[no_mangle]
    fn scram_free_client_first(cf: *mut scram_client_first);
    #[no_mangle]
    fn scram_free_server_first(sf: *mut scram_server_first);
    #[no_mangle]
    fn scram_free_client_final(cl: *mut scram_client_final);
    #[no_mangle]
    fn scram_free_server_final(sl: *mut scram_server_final);
    /* parser.h --- SCRAM parser.
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
    #[no_mangle]
    fn scram_parse_client_first(str: *const libc::c_char, len: size_t,
                                cf: *mut scram_client_first) -> libc::c_int;
    #[no_mangle]
    fn scram_parse_client_final(str: *const libc::c_char, len: size_t,
                                cl: *mut scram_client_final) -> libc::c_int;
    #[no_mangle]
    fn scram_print_server_first(cf: *mut scram_server_first,
                                out: *mut *mut libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn scram_print_server_final(sl: *mut scram_server_final,
                                out: *mut *mut libc::c_char) -> libc::c_int;
    /* memxor.h -- perform binary exclusive OR operation on memory blocks.
   Copyright (C) 2005, 2009-2021 Free Software Foundation, Inc.

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
    /* Written by Simon Josefsson.  The interface was inspired by memxor
   in Niels Möller's Nettle. */
    /* Compute binary exclusive OR of memory areas DEST and SRC, putting
   the result in DEST, of length N bytes.  Returns a pointer to
   DEST. */
    #[no_mangle]
    fn memxor(dest: *mut libc::c_void, src: *const libc::c_void, n: size_t)
     -> *mut libc::c_void;
    /* tools.h --- Shared client/server SCRAM code
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
    #[no_mangle]
    fn set_saltedpassword(sctx: *mut Gsasl_session, hash: Gsasl_hash,
                          hashbuf: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn _gsasl_hash(hash: Gsasl_hash, in_0: *const libc::c_char, inlen: size_t,
                   out: *mut libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn _gsasl_hmac(hash: Gsasl_hash, key: *const libc::c_char, keylen: size_t,
                   in_0: *const libc::c_char, inlen: size_t,
                   outhash: *mut libc::c_char) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type C2RustUnnamed = libc::c_uint;
pub const GSASL_GSSAPI_RELEASE_OID_SET_ERROR: C2RustUnnamed = 64;
pub const GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR: C2RustUnnamed = 63;
pub const GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR: C2RustUnnamed = 62;
pub const GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR: C2RustUnnamed = 61;
pub const GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR: C2RustUnnamed = 60;
pub const GSASL_SECURID_SERVER_NEED_NEW_PIN: C2RustUnnamed = 49;
pub const GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE: C2RustUnnamed = 48;
pub const GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR: C2RustUnnamed = 45;
pub const GSASL_GSSAPI_DISPLAY_NAME_ERROR: C2RustUnnamed = 44;
pub const GSASL_GSSAPI_ACQUIRE_CRED_ERROR: C2RustUnnamed = 43;
pub const GSASL_GSSAPI_WRAP_ERROR: C2RustUnnamed = 42;
pub const GSASL_GSSAPI_UNWRAP_ERROR: C2RustUnnamed = 41;
pub const GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR: C2RustUnnamed = 40;
pub const GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR: C2RustUnnamed = 39;
pub const GSASL_GSSAPI_IMPORT_NAME_ERROR: C2RustUnnamed = 38;
pub const GSASL_GSSAPI_RELEASE_BUFFER_ERROR: C2RustUnnamed = 37;
pub const GSASL_NO_OPENID20_REDIRECT_URL: C2RustUnnamed = 68;
pub const GSASL_NO_SAML20_REDIRECT_URL: C2RustUnnamed = 67;
pub const GSASL_NO_SAML20_IDP_IDENTIFIER: C2RustUnnamed = 66;
pub const GSASL_NO_CB_TLS_UNIQUE: C2RustUnnamed = 65;
pub const GSASL_NO_HOSTNAME: C2RustUnnamed = 59;
pub const GSASL_NO_SERVICE: C2RustUnnamed = 58;
pub const GSASL_NO_PIN: C2RustUnnamed = 57;
pub const GSASL_NO_PASSCODE: C2RustUnnamed = 56;
pub const GSASL_NO_PASSWORD: C2RustUnnamed = 55;
pub const GSASL_NO_AUTHZID: C2RustUnnamed = 54;
pub const GSASL_NO_AUTHID: C2RustUnnamed = 53;
pub const GSASL_NO_ANONYMOUS_TOKEN: C2RustUnnamed = 52;
pub const GSASL_NO_CALLBACK: C2RustUnnamed = 51;
pub const GSASL_NO_SERVER_CODE: C2RustUnnamed = 36;
pub const GSASL_NO_CLIENT_CODE: C2RustUnnamed = 35;
pub const GSASL_INTEGRITY_ERROR: C2RustUnnamed = 33;
pub const GSASL_AUTHENTICATION_ERROR: C2RustUnnamed = 31;
pub const GSASL_MECHANISM_PARSE_ERROR: C2RustUnnamed = 30;
pub const GSASL_SASLPREP_ERROR: C2RustUnnamed = 29;
pub const GSASL_CRYPTO_ERROR: C2RustUnnamed = 9;
pub const GSASL_BASE64_ERROR: C2RustUnnamed = 8;
pub const GSASL_MALLOC_ERROR: C2RustUnnamed = 7;
pub const GSASL_MECHANISM_CALLED_TOO_MANY_TIMES: C2RustUnnamed = 3;
pub const GSASL_UNKNOWN_MECHANISM: C2RustUnnamed = 2;
pub const GSASL_NEEDS_MORE: C2RustUnnamed = 1;
pub const GSASL_OK: C2RustUnnamed = 0;
pub type Gsasl_saslprep_flags = libc::c_uint;
pub const GSASL_ALLOW_UNASSIGNED: Gsasl_saslprep_flags = 1;
pub type Gsasl_property = libc::c_uint;
pub const GSASL_VALIDATE_OPENID20: Gsasl_property = 506;
pub const GSASL_VALIDATE_SAML20: Gsasl_property = 505;
pub const GSASL_VALIDATE_SECURID: Gsasl_property = 504;
pub const GSASL_VALIDATE_GSSAPI: Gsasl_property = 503;
pub const GSASL_VALIDATE_ANONYMOUS: Gsasl_property = 502;
pub const GSASL_VALIDATE_EXTERNAL: Gsasl_property = 501;
pub const GSASL_VALIDATE_SIMPLE: Gsasl_property = 500;
pub const GSASL_OPENID20_AUTHENTICATE_IN_BROWSER: Gsasl_property = 251;
pub const GSASL_SAML20_AUTHENTICATE_IN_BROWSER: Gsasl_property = 250;
pub const GSASL_OPENID20_OUTCOME_DATA: Gsasl_property = 22;
pub const GSASL_OPENID20_REDIRECT_URL: Gsasl_property = 21;
pub const GSASL_SAML20_REDIRECT_URL: Gsasl_property = 20;
pub const GSASL_SAML20_IDP_IDENTIFIER: Gsasl_property = 19;
pub const GSASL_CB_TLS_UNIQUE: Gsasl_property = 18;
pub const GSASL_SCRAM_STOREDKEY: Gsasl_property = 24;
pub const GSASL_SCRAM_SERVERKEY: Gsasl_property = 23;
pub const GSASL_SCRAM_SALTED_PASSWORD: Gsasl_property = 17;
pub const GSASL_SCRAM_SALT: Gsasl_property = 16;
pub const GSASL_SCRAM_ITER: Gsasl_property = 15;
pub const GSASL_QOP: Gsasl_property = 14;
pub const GSASL_QOPS: Gsasl_property = 13;
pub const GSASL_DIGEST_MD5_HASHED_PASSWORD: Gsasl_property = 12;
pub const GSASL_REALM: Gsasl_property = 11;
pub const GSASL_PIN: Gsasl_property = 10;
pub const GSASL_SUGGESTED_PIN: Gsasl_property = 9;
pub const GSASL_PASSCODE: Gsasl_property = 8;
pub const GSASL_GSSAPI_DISPLAY_NAME: Gsasl_property = 7;
pub const GSASL_HOSTNAME: Gsasl_property = 6;
pub const GSASL_SERVICE: Gsasl_property = 5;
pub const GSASL_ANONYMOUS_TOKEN: Gsasl_property = 4;
pub const GSASL_PASSWORD: Gsasl_property = 3;
pub const GSASL_AUTHZID: Gsasl_property = 2;
pub const GSASL_AUTHID: Gsasl_property = 1;
pub type Gsasl_hash = libc::c_uint;
pub const GSASL_HASH_SHA256: Gsasl_hash = 3;
pub const GSASL_HASH_SHA1: Gsasl_hash = 2;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_server_state {
    pub plus: bool,
    pub hash: Gsasl_hash,
    pub step: libc::c_int,
    pub cbind: *mut libc::c_char,
    pub gs2header: *mut libc::c_char,
    pub cfmb_str: *mut libc::c_char,
    pub sf_str: *mut libc::c_char,
    pub snonce: *mut libc::c_char,
    pub clientproof: *mut libc::c_char,
    pub storedkey: [libc::c_char; 32],
    pub serverkey: [libc::c_char; 32],
    pub authmessage: *mut libc::c_char,
    pub cbtlsunique: *mut libc::c_char,
    pub cbtlsuniquelen: size_t,
    pub cf: scram_client_first,
    pub sf: scram_server_first,
    pub cl: scram_client_final,
    pub sl: scram_server_final,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_server_final {
    pub verifier: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_client_final {
    pub cbind: *mut libc::c_char,
    pub nonce: *mut libc::c_char,
    pub proof: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_server_first {
    pub nonce: *mut libc::c_char,
    pub salt: *mut libc::c_char,
    pub iter: size_t,
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
/* Get size_t. */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_client_first {
    pub cbflag: libc::c_char,
    pub cbname: *mut libc::c_char,
    pub authzid: *mut libc::c_char,
    pub username: *mut libc::c_char,
    pub client_nonce: *mut libc::c_char,
}
unsafe extern "C" fn scram_start(mut sctx: *mut Gsasl_session,
                                 mut mech_data: *mut *mut libc::c_void,
                                 mut plus: bool, mut hash: Gsasl_hash)
 -> libc::c_int {
    let mut state: *mut scram_server_state = 0 as *mut scram_server_state;
    let mut buf: [libc::c_char; 18] = [0; 18];
    let mut rc: libc::c_int = 0;
    state =
        calloc(::std::mem::size_of::<scram_server_state>() as libc::c_ulong,
               1 as libc::c_int as libc::c_ulong) as *mut scram_server_state;
    if state.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    (*state).plus = plus;
    (*state).hash = hash;
    rc = gsasl_nonce(buf.as_mut_ptr(), 18 as libc::c_int as size_t);
    if !(rc != GSASL_OK as libc::c_int) {
        rc =
            gsasl_base64_to(buf.as_mut_ptr(), 18 as libc::c_int as size_t,
                            &mut (*state).snonce, 0 as *mut size_t);
        if !(rc != GSASL_OK as libc::c_int) {
            rc = gsasl_nonce(buf.as_mut_ptr(), 12 as libc::c_int as size_t);
            if !(rc != GSASL_OK as libc::c_int) {
                rc =
                    gsasl_base64_to(buf.as_mut_ptr(),
                                    12 as libc::c_int as size_t,
                                    &mut (*state).sf.salt, 0 as *mut size_t);
                if !(rc != GSASL_OK as libc::c_int) {
                    *mech_data = state as *mut libc::c_void;
                    return GSASL_OK as libc::c_int
                }
            }
        }
    }
    rpl_free((*state).sf.salt as *mut libc::c_void);
    rpl_free((*state).snonce as *mut libc::c_void);
    rpl_free(state as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn _gsasl_scram_sha1_server_start(mut sctx:
                                                            *mut Gsasl_session,
                                                        mut mech_data:
                                                            *mut *mut libc::c_void)
 -> libc::c_int {
    return scram_start(sctx, mech_data, 0 as libc::c_int != 0,
                       GSASL_HASH_SHA1);
}
#[no_mangle]
pub unsafe extern "C" fn _gsasl_scram_sha1_plus_server_start(mut sctx:
                                                                 *mut Gsasl_session,
                                                             mut mech_data:
                                                                 *mut *mut libc::c_void)
 -> libc::c_int {
    return scram_start(sctx, mech_data, 1 as libc::c_int != 0,
                       GSASL_HASH_SHA1);
}
#[no_mangle]
pub unsafe extern "C" fn _gsasl_scram_sha256_server_start(mut sctx:
                                                              *mut Gsasl_session,
                                                          mut mech_data:
                                                              *mut *mut libc::c_void)
 -> libc::c_int {
    return scram_start(sctx, mech_data, 0 as libc::c_int != 0,
                       GSASL_HASH_SHA256);
}
#[no_mangle]
pub unsafe extern "C" fn _gsasl_scram_sha256_plus_server_start(mut sctx:
                                                                   *mut Gsasl_session,
                                                               mut mech_data:
                                                                   *mut *mut libc::c_void)
 -> libc::c_int {
    return scram_start(sctx, mech_data, 1 as libc::c_int != 0,
                       GSASL_HASH_SHA256);
}
unsafe extern "C" fn extract_serverkey(mut state: *mut scram_server_state,
                                       mut b64: *const libc::c_char,
                                       mut buf: *mut libc::c_char)
 -> libc::c_int {
    let mut bin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut binlen: size_t = 0;
    let mut rc: libc::c_int = 0;
    rc = gsasl_base64_from(b64, strlen(b64), &mut bin, &mut binlen);
    if rc != GSASL_OK as libc::c_int { return rc }
    if binlen != gsasl_hash_length((*state).hash) {
        rpl_free(bin as *mut libc::c_void);
        return GSASL_AUTHENTICATION_ERROR as libc::c_int
    }
    memcpy(buf as *mut libc::c_void, bin as *const libc::c_void, binlen);
    rpl_free(bin as *mut libc::c_void);
    return GSASL_OK as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn _gsasl_scram_server_step(mut sctx:
                                                      *mut Gsasl_session,
                                                  mut mech_data:
                                                      *mut libc::c_void,
                                                  mut input:
                                                      *const libc::c_char,
                                                  mut input_len: size_t,
                                                  mut output:
                                                      *mut *mut libc::c_char,
                                                  mut output_len: *mut size_t)
 -> libc::c_int {
    let mut state: *mut scram_server_state =
        mech_data as *mut scram_server_state;
    let mut res: libc::c_int =
        GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int;
    let mut rc: libc::c_int = 0;
    *output = 0 as *mut libc::c_char;
    *output_len = 0 as libc::c_int as size_t;
    match (*state).step {
        0 => {
            if input_len == 0 as libc::c_int as libc::c_ulong {
                return GSASL_NEEDS_MORE as libc::c_int
            }
            let mut p: *const libc::c_char = 0 as *const libc::c_char;
            p = gsasl_property_get(sctx, GSASL_CB_TLS_UNIQUE);
            if (*state).plus as libc::c_int != 0 && p.is_null() {
                return GSASL_NO_CB_TLS_UNIQUE as libc::c_int
            }
            if !p.is_null() {
                rc =
                    gsasl_base64_from(p, strlen(p), &mut (*state).cbtlsunique,
                                      &mut (*state).cbtlsuniquelen);
                if rc != GSASL_OK as libc::c_int { return rc }
            }
            if scram_parse_client_first(input, input_len, &mut (*state).cf) <
                   0 as libc::c_int {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            /* In PLUS server mode, we require use of channel bindings. */
            if (*state).plus as libc::c_int != 0 &&
                   (*state).cf.cbflag as libc::c_int != 'p' as i32 {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            /* In non-PLUS mode, but where have channel bindings data (and
	   thus advertised PLUS) we reject a client 'y' cbflag. */
            if !(*state).plus &&
                   (*state).cbtlsuniquelen > 0 as libc::c_int as libc::c_ulong
                   && (*state).cf.cbflag as libc::c_int == 'y' as i32 {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            /* Check that username doesn't fail SASLprep. */
            let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
            rc =
                gsasl_saslprep((*state).cf.username, GSASL_ALLOW_UNASSIGNED,
                               &mut tmp, 0 as *mut libc::c_int);
            if rc != GSASL_OK as libc::c_int ||
                   *tmp as libc::c_int == '\u{0}' as i32 {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            gsasl_free(tmp as *mut libc::c_void);
            let mut p_0: *const libc::c_char = 0 as *const libc::c_char;
            /* Save "gs2-header" and "message-bare" for next step. */
            p_0 =
                memchr(input as *const libc::c_void, ',' as i32, input_len) as
                    *const libc::c_char;
            if p_0.is_null() {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            p_0 = p_0.offset(1);
            p_0 =
                memchr(p_0 as *const libc::c_void, ',' as i32,
                       input_len.wrapping_sub(p_0.wrapping_offset_from(input)
                                                  as libc::c_long as
                                                  libc::c_ulong)) as
                    *const libc::c_char;
            if p_0.is_null() {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            p_0 = p_0.offset(1);
            (*state).gs2header =
                malloc((p_0.wrapping_offset_from(input) as libc::c_long +
                            1 as libc::c_int as libc::c_long) as
                           libc::c_ulong) as *mut libc::c_char;
            if (*state).gs2header.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            memcpy((*state).gs2header as *mut libc::c_void,
                   input as *const libc::c_void,
                   p_0.wrapping_offset_from(input) as libc::c_long as
                       libc::c_ulong);
            *(*state).gs2header.offset(p_0.wrapping_offset_from(input) as
                                           libc::c_long as isize) =
                '\u{0}' as i32 as libc::c_char;
            (*state).cfmb_str =
                malloc(input_len.wrapping_sub(p_0.wrapping_offset_from(input)
                                                  as libc::c_long as
                                                  libc::c_ulong).wrapping_add(1
                                                                                  as
                                                                                  libc::c_int
                                                                                  as
                                                                                  libc::c_ulong))
                    as *mut libc::c_char;
            if (*state).cfmb_str.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            memcpy((*state).cfmb_str as *mut libc::c_void,
                   p_0 as *const libc::c_void,
                   input_len.wrapping_sub(p_0.wrapping_offset_from(input) as
                                              libc::c_long as libc::c_ulong));
            *(*state).cfmb_str.offset(input_len.wrapping_sub(p_0.wrapping_offset_from(input)
                                                                 as
                                                                 libc::c_long
                                                                 as
                                                                 libc::c_ulong)
                                          as isize) =
                '\u{0}' as i32 as libc::c_char;
            /* Create new nonce. */
            let mut cnlen: size_t = strlen((*state).cf.client_nonce);
            let mut snlen: size_t = strlen((*state).snonce);
            (*state).sf.nonce =
                malloc(cnlen.wrapping_add(snlen).wrapping_add(1 as libc::c_int
                                                                  as
                                                                  libc::c_ulong))
                    as *mut libc::c_char;
            if (*state).sf.nonce.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            memcpy((*state).sf.nonce as *mut libc::c_void,
                   (*state).cf.client_nonce as *const libc::c_void, cnlen);
            memcpy((*state).sf.nonce.offset(cnlen as isize) as
                       *mut libc::c_void,
                   (*state).snonce as *const libc::c_void, snlen);
            *(*state).sf.nonce.offset(cnlen.wrapping_add(snlen) as isize) =
                '\u{0}' as i32 as libc::c_char;
            rc = gsasl_property_set(sctx, GSASL_AUTHID, (*state).cf.username);
            if rc != GSASL_OK as libc::c_int { return rc }
            rc = gsasl_property_set(sctx, GSASL_AUTHZID, (*state).cf.authzid);
            if rc != GSASL_OK as libc::c_int { return rc }
            let mut p_1: *const libc::c_char =
                gsasl_property_get(sctx, GSASL_SCRAM_ITER);
            if !p_1.is_null() {
                (*state).sf.iter =
                    strtoul(p_1, 0 as *mut *mut libc::c_char,
                            10 as libc::c_int)
            }
            if p_1.is_null() ||
                   (*state).sf.iter == 0 as libc::c_int as libc::c_ulong ||
                   (*state).sf.iter ==
                       (9223372036854775807 as libc::c_long as
                            libc::c_ulong).wrapping_mul(2 as
                                                            libc::c_ulong).wrapping_add(1
                                                                                            as
                                                                                            libc::c_ulong)
               {
                (*state).sf.iter = 4096 as libc::c_int as size_t
            }
            /* Save salt/iter as properties, so that client callback can
	     access them. */
            let mut str: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut n: libc::c_int = 0;
            n =
                asprintf(&mut str as *mut *mut libc::c_char,
                         b"%zu\x00" as *const u8 as *const libc::c_char,
                         (*state).sf.iter);
            if n < 0 as libc::c_int || str.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            rc = gsasl_property_set(sctx, GSASL_SCRAM_ITER, str);
            rpl_free(str as *mut libc::c_void);
            if rc != GSASL_OK as libc::c_int { return rc }
            let mut p_2: *const libc::c_char =
                gsasl_property_get(sctx, GSASL_SCRAM_SALT);
            if !p_2.is_null() {
                rpl_free((*state).sf.salt as *mut libc::c_void);
                (*state).sf.salt = strdup(p_2)
            } else {
                rc =
                    gsasl_property_set(sctx, GSASL_SCRAM_SALT,
                                       (*state).sf.salt);
                if rc != GSASL_OK as libc::c_int { return rc }
            }
            rc =
                scram_print_server_first(&mut (*state).sf,
                                         &mut (*state).sf_str);
            if rc != 0 as libc::c_int {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            *output = strdup((*state).sf_str);
            if (*output).is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            *output_len = strlen(*output);
            (*state).step += 1;
            return GSASL_NEEDS_MORE as libc::c_int
        }
        1 => {
            if scram_parse_client_final(input, input_len, &mut (*state).cl) <
                   0 as libc::c_int {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            if strcmp((*state).cl.nonce, (*state).sf.nonce) !=
                   0 as libc::c_int {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            /* Base64 decode the c= field and check that it matches
	   client-first.  Also check channel binding data. */
            let mut len: size_t = 0;
            rc =
                gsasl_base64_from((*state).cl.cbind,
                                  strlen((*state).cl.cbind),
                                  &mut (*state).cbind, &mut len);
            if rc != 0 as libc::c_int { return rc }
            if (*state).cf.cbflag as libc::c_int == 'p' as i32 {
                if len < strlen((*state).gs2header) {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
                if memcmp((*state).cbind as *const libc::c_void,
                          (*state).gs2header as *const libc::c_void,
                          strlen((*state).gs2header)) != 0 as libc::c_int {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
                if len.wrapping_sub(strlen((*state).gs2header)) !=
                       (*state).cbtlsuniquelen {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
                if memcmp((*state).cbind.offset(strlen((*state).gs2header) as
                                                    isize) as
                              *const libc::c_void,
                          (*state).cbtlsunique as *const libc::c_void,
                          (*state).cbtlsuniquelen) != 0 as libc::c_int {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
            } else {
                if len != strlen((*state).gs2header) {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
                if memcmp((*state).cbind as *const libc::c_void,
                          (*state).gs2header as *const libc::c_void, len) !=
                       0 as libc::c_int {
                    return GSASL_AUTHENTICATION_ERROR as libc::c_int
                }
            }
            /* Base64 decode client proof and check that length matches
	   hash size. */
            let mut len_0: size_t = 0;
            rc =
                gsasl_base64_from((*state).cl.proof,
                                  strlen((*state).cl.proof),
                                  &mut (*state).clientproof, &mut len_0);
            if rc != 0 as libc::c_int { return rc }
            if gsasl_hash_length((*state).hash) != len_0 {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            let mut p_3: *const libc::c_char = 0 as *const libc::c_char;
            let mut q: *const libc::c_char = 0 as *const libc::c_char;
            /* Get StoredKey and ServerKey */
            p_3 = gsasl_property_get(sctx, GSASL_SCRAM_SERVERKEY);
            if !p_3.is_null() &&
                   {
                       q = gsasl_property_get(sctx, GSASL_SCRAM_STOREDKEY);
                       !q.is_null()
                   } {
                rc =
                    extract_serverkey(state, p_3,
                                      (*state).serverkey.as_mut_ptr());
                if rc != GSASL_OK as libc::c_int { return rc }
                rc =
                    extract_serverkey(state, q,
                                      (*state).storedkey.as_mut_ptr());
                if rc != GSASL_OK as libc::c_int { return rc }
            } else {
                p_3 = gsasl_property_get(sctx, GSASL_PASSWORD);
                if !p_3.is_null() {
                    let mut salt: *mut libc::c_char = 0 as *mut libc::c_char;
                    let mut saltlen: size_t = 0;
                    let mut saltedpassword: [libc::c_char; 32] = [0; 32];
                    let mut clientkey: [libc::c_char; 32] = [0; 32];
                    let mut b64str: *mut libc::c_char =
                        0 as *mut libc::c_char;
                    rc =
                        gsasl_base64_from((*state).sf.salt,
                                          strlen((*state).sf.salt), &mut salt,
                                          &mut saltlen);
                    if rc != GSASL_OK as libc::c_int { return rc }
                    rc =
                        gsasl_scram_secrets_from_password((*state).hash, p_3,
                                                          (*state).sf.iter as
                                                              libc::c_uint,
                                                          salt, saltlen,
                                                          saltedpassword.as_mut_ptr(),
                                                          clientkey.as_mut_ptr(),
                                                          (*state).serverkey.as_mut_ptr(),
                                                          (*state).storedkey.as_mut_ptr());
                    if rc != GSASL_OK as libc::c_int { return rc }
                    rc =
                        set_saltedpassword(sctx, (*state).hash,
                                           saltedpassword.as_mut_ptr());
                    if rc != GSASL_OK as libc::c_int { return rc }
                    rc =
                        gsasl_base64_to((*state).serverkey.as_mut_ptr(),
                                        gsasl_hash_length((*state).hash),
                                        &mut b64str, 0 as *mut size_t);
                    if rc != GSASL_OK as libc::c_int { return rc }
                    rc =
                        gsasl_property_set(sctx, GSASL_SCRAM_SERVERKEY,
                                           b64str);
                    rpl_free(b64str as *mut libc::c_void);
                    if rc != GSASL_OK as libc::c_int { return rc }
                    rc =
                        gsasl_base64_to((*state).storedkey.as_mut_ptr(),
                                        gsasl_hash_length((*state).hash),
                                        &mut b64str, 0 as *mut size_t);
                    if rc != 0 as libc::c_int { return rc }
                    rc =
                        gsasl_property_set(sctx, GSASL_SCRAM_STOREDKEY,
                                           b64str);
                    rpl_free(b64str as *mut libc::c_void);
                    if rc != GSASL_OK as libc::c_int { return rc }
                    gsasl_free(salt as *mut libc::c_void);
                } else { return GSASL_NO_PASSWORD as libc::c_int }
            }
            /* Compute AuthMessage */
            let mut len_1: size_t = 0;
            let mut n_0: libc::c_int = 0;
            /* Get client-final-message-without-proof. */
            p_3 =
                memmem(input as *const libc::c_void, input_len,
                       b",p=\x00" as *const u8 as *const libc::c_char as
                           *const libc::c_void, 3 as libc::c_int as size_t) as
                    *const libc::c_char;
            if p_3.is_null() {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            len_1 = p_3.wrapping_offset_from(input) as libc::c_long as size_t;
            n_0 =
                asprintf(&mut (*state).authmessage as *mut *mut libc::c_char,
                         b"%s,%.*s,%.*s\x00" as *const u8 as
                             *const libc::c_char, (*state).cfmb_str,
                         strlen((*state).sf_str) as libc::c_int,
                         (*state).sf_str, len_1 as libc::c_int, input);
            if n_0 <= 0 as libc::c_int || (*state).authmessage.is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            /* Check client proof. */
            let mut clientsignature: [libc::c_char; 32] = [0; 32];
            let mut maybe_storedkey: [libc::c_char; 32] = [0; 32];
            /* ClientSignature := HMAC(StoredKey, AuthMessage) */
            rc =
                _gsasl_hmac((*state).hash, (*state).storedkey.as_mut_ptr(),
                            gsasl_hash_length((*state).hash),
                            (*state).authmessage,
                            strlen((*state).authmessage),
                            clientsignature.as_mut_ptr());
            if rc != 0 as libc::c_int { return rc }
            /* ClientKey := ClientProof XOR ClientSignature */
            memxor(clientsignature.as_mut_ptr() as *mut libc::c_void,
                   (*state).clientproof as *const libc::c_void,
                   gsasl_hash_length((*state).hash));
            rc =
                _gsasl_hash((*state).hash, clientsignature.as_mut_ptr(),
                            gsasl_hash_length((*state).hash),
                            maybe_storedkey.as_mut_ptr());
            if rc != 0 as libc::c_int { return rc }
            rc =
                memcmp((*state).storedkey.as_mut_ptr() as *const libc::c_void,
                       maybe_storedkey.as_mut_ptr() as *const libc::c_void,
                       gsasl_hash_length((*state).hash));
            if rc != 0 as libc::c_int {
                return GSASL_AUTHENTICATION_ERROR as libc::c_int
            }
            /* Generate server verifier. */
            let mut serversignature: [libc::c_char; 32] = [0; 32];
            /* ServerSignature := HMAC(ServerKey, AuthMessage) */
            rc =
                _gsasl_hmac((*state).hash, (*state).serverkey.as_mut_ptr(),
                            gsasl_hash_length((*state).hash),
                            (*state).authmessage,
                            strlen((*state).authmessage),
                            serversignature.as_mut_ptr());
            if rc != 0 as libc::c_int { return rc }
            rc =
                gsasl_base64_to(serversignature.as_mut_ptr(),
                                gsasl_hash_length((*state).hash),
                                &mut (*state).sl.verifier, 0 as *mut size_t);
            if rc != 0 as libc::c_int { return rc }
            rc = scram_print_server_final(&mut (*state).sl, output);
            if rc != 0 as libc::c_int {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            *output_len = strlen(*output);
            (*state).step += 1;
            return GSASL_OK as libc::c_int
        }
        _ => { }
    }
    return res;
}
/* scram.h --- Prototypes for SCRAM mechanism
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
#[no_mangle]
pub unsafe extern "C" fn _gsasl_scram_server_finish(mut sctx:
                                                        *mut Gsasl_session,
                                                    mut mech_data:
                                                        *mut libc::c_void) {
    let mut state: *mut scram_server_state =
        mech_data as *mut scram_server_state;
    if state.is_null() { return }
    rpl_free((*state).cbind as *mut libc::c_void);
    rpl_free((*state).gs2header as *mut libc::c_void);
    rpl_free((*state).cfmb_str as *mut libc::c_void);
    rpl_free((*state).sf_str as *mut libc::c_void);
    rpl_free((*state).snonce as *mut libc::c_void);
    rpl_free((*state).clientproof as *mut libc::c_void);
    rpl_free((*state).authmessage as *mut libc::c_void);
    rpl_free((*state).cbtlsunique as *mut libc::c_void);
    scram_free_client_first(&mut (*state).cf);
    scram_free_server_first(&mut (*state).sf);
    scram_free_client_final(&mut (*state).cl);
    scram_free_server_final(&mut (*state).sl);
    rpl_free(state as *mut libc::c_void);
}
