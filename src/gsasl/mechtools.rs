use ::libc;
extern "C" {
    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char,
                _: ...) -> libc::c_int;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    fn memchr(_: *const libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char,
               _: libc::c_ulong) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
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
    fn rpl_free(_: *mut libc::c_void);
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn gc_sha1(in_0: *const libc::c_void, inlen: size_t,
               resbuf: *mut libc::c_void) -> Gc_rc;
    fn gc_sha256(in_0: *const libc::c_void, inlen: size_t,
                 resbuf: *mut libc::c_void) -> Gc_rc;
    fn gc_hmac_sha1(key: *const libc::c_void, keylen: size_t,
                    in_0: *const libc::c_void, inlen: size_t,
                    resbuf: *mut libc::c_char) -> Gc_rc;
    fn gc_hmac_sha256(key: *const libc::c_void, keylen: size_t,
                      in_0: *const libc::c_void, inlen: size_t,
                      resbuf: *mut libc::c_char) -> Gc_rc;
    /* Derive cryptographic keys using PKCS#5 PBKDF2 (RFC 2898) from a
   password P of length PLEN, with salt S of length SLEN, placing the
   result in pre-allocated buffer DK of length DKLEN.  The PRF is hard
   coded to be HMAC with HASH.  An iteration count is specified in C
   (> 0), where a larger value means this function take more time
   (typical iteration counts are 1000-20000).  This function
   "stretches" the key to be exactly dkLen bytes long.  GC_OK is
   returned on success, otherwise a Gc_rc error code is returned.  */
    fn gc_pbkdf2_hmac(hash: Gc_hash, P: *const libc::c_char, Plen: size_t,
                      S: *const libc::c_char, Slen: size_t, c: libc::c_uint,
                      DK: *mut libc::c_char, dkLen: size_t) -> Gc_rc;
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
pub type Gsasl_hash = libc::c_uint;
pub const GSASL_HASH_SHA256: Gsasl_hash = 3;
pub const GSASL_HASH_SHA1: Gsasl_hash = 2;
pub type C2RustUnnamed_0 = libc::c_uint;
pub const GSASL_HASH_MAX_SIZE: C2RustUnnamed_0 = 32;
pub const GSASL_HASH_SHA256_SIZE: C2RustUnnamed_0 = 32;
pub const GSASL_HASH_SHA1_SIZE: C2RustUnnamed_0 = 20;
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
/* Get size_t. */
pub type Gc_rc = libc::c_uint;
pub const GC_PKCS5_DERIVED_KEY_TOO_LONG: Gc_rc = 8;
pub const GC_PKCS5_INVALID_DERIVED_KEY_LENGTH: Gc_rc = 7;
pub const GC_PKCS5_INVALID_ITERATION_COUNT: Gc_rc = 6;
pub const GC_INVALID_HASH: Gc_rc = 5;
pub const GC_INVALID_CIPHER: Gc_rc = 4;
pub const GC_RANDOM_ERROR: Gc_rc = 3;
pub const GC_INIT_ERROR: Gc_rc = 2;
pub const GC_MALLOC_ERROR: Gc_rc = 1;
pub const GC_OK: Gc_rc = 0;
/* Hash types. */
pub type Gc_hash = libc::c_uint;
pub const GC_SM3: Gc_hash = 9;
pub const GC_SHA224: Gc_hash = 8;
pub const GC_SHA512: Gc_hash = 7;
pub const GC_SHA384: Gc_hash = 6;
pub const GC_SHA256: Gc_hash = 5;
pub const GC_RMD160: Gc_hash = 4;
pub const GC_MD2: Gc_hash = 3;
pub const GC_SHA1: Gc_hash = 2;
pub const GC_MD5: Gc_hash = 1;
pub const GC_MD4: Gc_hash = 0;
/* mechtools.c --- Helper functions available for use by any mechanism.
 * Copyright (C) 2010-2021 Simon Josefsson
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
/* Get strcmp. */
/* Get malloc, free. */
/* Get asprintf. */
/* Get error codes. */
/* Gnulib gc.h */
/* Create in AUTHZID a newly allocated copy of STR where =2C is
   replaced with , and =3D is replaced with =.  Return GSASL_OK on
   success, GSASL_MALLOC_ERROR on memory errors, GSASL_PARSE_ERRORS if
   string contains any unencoded ',' or incorrectly encoded
   sequence.  */
unsafe extern "C" fn unescape_authzid(mut str: *const libc::c_char,
                                      mut len: size_t,
                                      mut authzid: *mut *mut libc::c_char)
 -> libc::c_int {
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    if !memchr(str as *const libc::c_void, ',' as i32, len).is_null() {
        return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
    }
    *authzid =
        malloc(len.wrapping_add(1 as libc::c_int as libc::c_ulong)) as
            *mut libc::c_char;
    p = *authzid;
    if p.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    while len > 0 as libc::c_int as libc::c_ulong && *str as libc::c_int != 0
          {
        if len >= 3 as libc::c_int as libc::c_ulong &&
               *str.offset(0 as libc::c_int as isize) as libc::c_int ==
                   '=' as i32 &&
               *str.offset(1 as libc::c_int as isize) as libc::c_int ==
                   '2' as i32 &&
               *str.offset(2 as libc::c_int as isize) as libc::c_int ==
                   'C' as i32 {
            let fresh0 = p;
            p = p.offset(1);
            *fresh0 = ',' as i32 as libc::c_char;
            str = str.offset(3 as libc::c_int as isize);
            len =
                (len as
                     libc::c_ulong).wrapping_sub(3 as libc::c_int as
                                                     libc::c_ulong) as size_t
                    as size_t
        } else if len >= 3 as libc::c_int as libc::c_ulong &&
                      *str.offset(0 as libc::c_int as isize) as libc::c_int ==
                          '=' as i32 &&
                      *str.offset(1 as libc::c_int as isize) as libc::c_int ==
                          '3' as i32 &&
                      *str.offset(2 as libc::c_int as isize) as libc::c_int ==
                          'D' as i32 {
            let fresh1 = p;
            p = p.offset(1);
            *fresh1 = '=' as i32 as libc::c_char;
            str = str.offset(3 as libc::c_int as isize);
            len =
                (len as
                     libc::c_ulong).wrapping_sub(3 as libc::c_int as
                                                     libc::c_ulong) as size_t
                    as size_t
        } else if *str.offset(0 as libc::c_int as isize) as libc::c_int ==
                      '=' as i32 {
            rpl_free(*authzid as *mut libc::c_void);
            *authzid = 0 as *mut libc::c_char;
            return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
        } else {
            let fresh2 = p;
            p = p.offset(1);
            *fresh2 = *str;
            str = str.offset(1);
            len = len.wrapping_sub(1)
        }
    }
    *p = '\u{0}' as i32 as libc::c_char;
    return GSASL_OK as libc::c_int;
}
/* Parse the GS2 header containing flags and authorization identity.
   Put authorization identity (or NULL) in AUTHZID and length of
   header in HEADERLEN.  Return GSASL_OK on success or an error
   code.*/
#[no_mangle]
pub unsafe extern "C" fn _gsasl_parse_gs2_header(mut data:
                                                     *const libc::c_char,
                                                 mut len: size_t,
                                                 mut authzid:
                                                     *mut *mut libc::c_char,
                                                 mut headerlen: *mut size_t)
 -> libc::c_int {
    let mut authzid_endptr: *mut libc::c_char = 0 as *mut libc::c_char;
    if len < 3 as libc::c_int as libc::c_ulong {
        return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
    }
    if strncmp(data, b"n,,\x00" as *const u8 as *const libc::c_char,
               3 as libc::c_int as libc::c_ulong) == 0 as libc::c_int {
        *headerlen = 3 as libc::c_int as size_t;
        *authzid = 0 as *mut libc::c_char
    } else if strncmp(data, b"n,a=\x00" as *const u8 as *const libc::c_char,
                      4 as libc::c_int as libc::c_ulong) == 0 as libc::c_int
                  &&
                  {
                      authzid_endptr =
                          memchr(data.offset(4 as libc::c_int as isize) as
                                     *const libc::c_void, ',' as i32,
                                 len.wrapping_sub(4 as libc::c_int as
                                                      libc::c_ulong)) as
                              *mut libc::c_char;
                      !authzid_endptr.is_null()
                  } {
        let mut res: libc::c_int = 0;
        if authzid_endptr.is_null() {
            return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
        }
        res =
            unescape_authzid(data.offset(4 as libc::c_int as isize),
                             authzid_endptr.offset_from(data.offset(4))
                                 as libc::c_long as size_t, authzid);
        if res != GSASL_OK as libc::c_int { return res }
        *headerlen = (authzid_endptr.offset_from(data) + 1) as size_t
    } else { return GSASL_MECHANISM_PARSE_ERROR as libc::c_int }
    return GSASL_OK as libc::c_int;
}
/* Return newly allocated copy of STR with all occurrences of ','
   replaced with =2C and '=' with '=3D', or return NULL on memory
   allocation errors.  */
unsafe extern "C" fn escape_authzid(mut str: *const libc::c_char)
 -> *mut libc::c_char {
    let mut out: *mut libc::c_char =
        malloc(strlen(str).wrapping_mul(3 as libc::c_int as
                                            libc::c_ulong).wrapping_add(1 as
                                                                            libc::c_int
                                                                            as
                                                                            libc::c_ulong))
            as *mut libc::c_char;
    let mut p: *mut libc::c_char = out;
    if out.is_null() { return 0 as *mut libc::c_char }
    while *str != 0 {
        if *str as libc::c_int == ',' as i32 {
            memcpy(p as *mut libc::c_void,
                   b"=2C\x00" as *const u8 as *const libc::c_char as
                       *const libc::c_void,
                   3 as libc::c_int as libc::c_ulong);
            p = p.offset(3 as libc::c_int as isize)
        } else if *str as libc::c_int == '=' as i32 {
            memcpy(p as *mut libc::c_void,
                   b"=3D\x00" as *const u8 as *const libc::c_char as
                       *const libc::c_void,
                   3 as libc::c_int as libc::c_ulong);
            p = p.offset(3 as libc::c_int as isize)
        } else { *p = *str; p = p.offset(1) }
        str = str.offset(1)
    }
    *p = '\u{0}' as i32 as libc::c_char;
    return out;
}
/* Generate a newly allocated GS2 header, escaping authzid
   appropriately, and appending EXTRA. */
#[no_mangle]
pub unsafe extern "C" fn _gsasl_gs2_generate_header(mut nonstd: bool,
                                                    mut cbflag: libc::c_char,
                                                    mut cbname:
                                                        *const libc::c_char,
                                                    mut authzid:
                                                        *const libc::c_char,
                                                    mut extralen: size_t,
                                                    mut extra:
                                                        *const libc::c_char,
                                                    mut gs2h:
                                                        *mut *mut libc::c_char,
                                                    mut gs2hlen: *mut size_t)
 -> libc::c_int {
    let mut elen: libc::c_int = extralen as libc::c_int;
    let mut gs2cbflag: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: libc::c_int = 0;
    if cbflag as libc::c_int == 'p' as i32 {
        len =
            asprintf(&mut gs2cbflag as *mut *mut libc::c_char,
                     b"p=%s\x00" as *const u8 as *const libc::c_char, cbname)
    } else if cbflag as libc::c_int == 'n' as i32 {
        len =
            asprintf(&mut gs2cbflag as *mut *mut libc::c_char,
                     b"n\x00" as *const u8 as *const libc::c_char)
    } else if cbflag as libc::c_int == 'y' as i32 {
        len =
            asprintf(&mut gs2cbflag as *mut *mut libc::c_char,
                     b"y\x00" as *const u8 as *const libc::c_char)
    } else {
        /* internal caller error */
        return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
    }
    if len <= 0 as libc::c_int || gs2cbflag.is_null() {
        return GSASL_MALLOC_ERROR as libc::c_int
    }
    if !authzid.is_null() {
        let mut escaped_authzid: *mut libc::c_char = escape_authzid(authzid);
        if escaped_authzid.is_null() {
            rpl_free(gs2cbflag as *mut libc::c_void);
            return GSASL_MALLOC_ERROR as libc::c_int
        }
        len =
            asprintf(gs2h,
                     b"%s%s,a=%s,%.*s\x00" as *const u8 as
                         *const libc::c_char,
                     if nonstd as libc::c_int != 0 {
                         b"F,\x00" as *const u8 as *const libc::c_char
                     } else { b"\x00" as *const u8 as *const libc::c_char },
                     gs2cbflag, escaped_authzid, elen, extra);
        rpl_free(escaped_authzid as *mut libc::c_void);
    } else {
        len =
            asprintf(gs2h,
                     b"%s%s,,%.*s\x00" as *const u8 as *const libc::c_char,
                     if nonstd as libc::c_int != 0 {
                         b"F,\x00" as *const u8 as *const libc::c_char
                     } else { b"\x00" as *const u8 as *const libc::c_char },
                     gs2cbflag, elen, extra)
    }
    rpl_free(gs2cbflag as *mut libc::c_void);
    if len <= 0 as libc::c_int || gs2h.is_null() {
        return GSASL_MALLOC_ERROR as libc::c_int
    }
    *gs2hlen = len as size_t;
    return GSASL_OK as libc::c_int;
}
/* Hex encode binary octet array IN of INLEN length, putting the hex
   encoded string in OUT which must have room for the data and
   terminating zero, i.e., 2*INLEN+1. */
#[no_mangle]
pub unsafe extern "C" fn _gsasl_hex_encode(mut in_0: *const libc::c_char,
                                           mut inlen: size_t,
                                           mut out: *mut libc::c_char) {
    let mut i: size_t = 0;
    let mut p: *const libc::c_char = in_0;
    i = 0 as libc::c_int as size_t;
    while i < (2 as libc::c_int as libc::c_ulong).wrapping_mul(inlen) {
        let fresh3 = p;
        p = p.offset(1);
        let mut c: libc::c_uchar = *fresh3 as libc::c_uchar;
        let fresh4 = i;
        i = i.wrapping_add(1);
        *out.offset(fresh4 as isize) =
            (*::std::mem::transmute::<&[u8; 17],
                                      &[libc::c_char; 17]>(b"0123456789abcdef\x00"))[(c
                                                                                          as
                                                                                          libc::c_int
                                                                                          >>
                                                                                          4
                                                                                              as
                                                                                              libc::c_int)
                                                                                         as
                                                                                         usize];
        let fresh5 = i;
        i = i.wrapping_add(1);
        *out.offset(fresh5 as isize) =
            (*::std::mem::transmute::<&[u8; 17],
                                      &[libc::c_char; 17]>(b"0123456789abcdef\x00"))[(c
                                                                                          as
                                                                                          libc::c_int
                                                                                          &
                                                                                          0xf
                                                                                              as
                                                                                              libc::c_int)
                                                                                         as
                                                                                         usize]
    }
    *out.offset(i as isize) = '\u{0}' as i32 as libc::c_char;
}
unsafe extern "C" fn hexdigit_to_char(mut hexdigit: libc::c_char)
 -> libc::c_char {
    if hexdigit as libc::c_int >= '0' as i32 &&
           hexdigit as libc::c_int <= '9' as i32 {
        return (hexdigit as libc::c_int - '0' as i32) as libc::c_char
    }
    if hexdigit as libc::c_int >= 'a' as i32 &&
           hexdigit as libc::c_int <= 'f' as i32 {
        return (hexdigit as libc::c_int - 'a' as i32 + 10 as libc::c_int) as
                   libc::c_char
    }
    return 0 as libc::c_int as libc::c_char;
}
unsafe extern "C" fn hex_to_char(mut u: libc::c_char, mut l: libc::c_char)
 -> libc::c_char {
    return (hexdigit_to_char(u) as libc::c_uchar as libc::c_int *
                16 as libc::c_int + hexdigit_to_char(l) as libc::c_int) as
               libc::c_char;
}
/* Hex decode string HEXSTR containing only hex "0-9A-F" characters
   into binary buffer BIN which must have room for data, i.e., strlen
   (hexstr)/2. */
#[no_mangle]
pub unsafe extern "C" fn _gsasl_hex_decode(mut hexstr: *const libc::c_char,
                                           mut bin: *mut libc::c_char) {
    while *hexstr != 0 {
        *bin =
            hex_to_char(*hexstr.offset(0 as libc::c_int as isize),
                        *hexstr.offset(1 as libc::c_int as isize));
        hexstr = hexstr.offset(2 as libc::c_int as isize);
        bin = bin.offset(1)
    };
}
/* Return whether string contains hex "0-9a-f" symbols only. */
#[no_mangle]
pub unsafe extern "C" fn _gsasl_hex_p(mut hexstr: *const libc::c_char)
 -> bool {
    static mut hexalpha: &'static [u8; 17] = b"0123456789abcdef\x00";
    while *hexstr != 0 {
        if strchr(hexalpha.as_ptr() as *const libc::c_char, *hexstr as libc::c_int).is_null() {
            return 0 as libc::c_int != 0
        }
        hexstr = hexstr.offset(1)
    }
    return 1 as libc::c_int != 0;
}
/*
 * _gsasl_hash:
 * @hash: a %Gsasl_hash hash algorithm identifier, e.g. #GSASL_HASH_SHA256.
 * @in: input character array of data to hash.
 * @inlen: length of input character array of data to hash.
 * @outhash: buffer to hold hash of data.
 *
 * Compute hash of data using the @hash algorithm.  The @outhash
 * buffer must have room to hold the size of @hash's output; a safe
 * value that have room for all possible outputs is
 * %GSASL_HASH_MAX_SIZE.
 *
 * Return value: Returns %GSASL_OK iff successful.
 *
 * Since: 1.10
 **/
#[no_mangle]
pub unsafe extern "C" fn _gsasl_hash(mut hash: Gsasl_hash,
                                     mut in_0: *const libc::c_char,
                                     mut inlen: size_t,
                                     mut outhash: *mut libc::c_char)
 -> libc::c_int {
    let mut rc: libc::c_int = 0;
    if hash as libc::c_uint == GSASL_HASH_SHA1 as libc::c_int as libc::c_uint
       {
        rc =
            gc_sha1(in_0 as *const libc::c_void, inlen,
                    outhash as *mut libc::c_void) as libc::c_int
    } else if hash as libc::c_uint ==
                  GSASL_HASH_SHA256 as libc::c_int as libc::c_uint {
        rc =
            gc_sha256(in_0 as *const libc::c_void, inlen,
                      outhash as *mut libc::c_void) as libc::c_int
    } else { rc = GSASL_CRYPTO_ERROR as libc::c_int }
    return rc;
}
/*
 * _gsasl_hmac:
 * @hash: a %Gsasl_hash hash algorithm identifier, e.g. #GSASL_HASH_SHA256.
 * @key: input character array with key to use.
 * @keylen: length of input character array with key to use.
 * @in: input character array of data to hash.
 * @inlen: length of input character array of data to hash.
 * @outhash: buffer to hold keyed hash of data.
 *
 * Compute keyed checksum of data using HMAC for the @hash algorithm.
 * The @outhash buffer must have room to hold the size of @hash's
 * output; a safe value that have room for all possible outputs is
 * %GSASL_HASH_MAX_SIZE.
 *
 * Return value: Returns %GSASL_OK iff successful.
 *
 * Since: 1.10
 **/
#[no_mangle]
pub unsafe extern "C" fn _gsasl_hmac(mut hash: Gsasl_hash,
                                     mut key: *const libc::c_char,
                                     mut keylen: size_t,
                                     mut in_0: *const libc::c_char,
                                     mut inlen: size_t,
                                     mut outhash: *mut libc::c_char)
 -> libc::c_int {
    let mut rc: libc::c_int = 0;
    if hash as libc::c_uint == GSASL_HASH_SHA1 as libc::c_int as libc::c_uint
       {
        rc =
            gc_hmac_sha1(key as *const libc::c_void, keylen,
                         in_0 as *const libc::c_void, inlen, outhash) as
                libc::c_int
    } else if hash as libc::c_uint ==
                  GSASL_HASH_SHA256 as libc::c_int as libc::c_uint {
        rc =
            gc_hmac_sha256(key as *const libc::c_void, keylen,
                           in_0 as *const libc::c_void, inlen, outhash) as
                libc::c_int
    } else { rc = GSASL_CRYPTO_ERROR as libc::c_int }
    return rc;
}
/* mechtools.h --- Helper functions available for use by any mechanism.
 * Copyright (C) 2010-2021 Simon Josefsson
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
/* Get bool. */
/*
 * gsasl_pbkdf2:
 * @hash: a %Gsasl_hash hash algorithm identifier.
 * @password: input character array with password to use.
 * @passwordlen: length of @password.
 * @salt: input character array with salt, typically a short string.
 * @saltlen: length of @salt.
 * @c: iteration count, typically larger than 4096.
 * @dk: output buffer, must be able to hold @dklen.
 * @dklen: length of output buffer, or 0 to indicate @hash output size.
 *
 * Hash and salt password according to PBKDF2 algorithm with the @hash
 * function used in HMAC.  This function can be used to prepare SCRAM
 * SaltedPassword values for the %GSASL_SCRAM_SALTED_PASSWORD
 * property.  Note that password should normally be prepared using
 * gsasl_saslprep(GSASL_ALLOW_UNASSIGNED) before calling this
 * function.
 *
 * Return value: Returns %GSASL_OK if successful, or error code.
 *
 * Since: 1.10
 **/
#[no_mangle]
pub unsafe extern "C" fn _gsasl_pbkdf2(mut hash: Gsasl_hash,
                                       mut password: *const libc::c_char,
                                       mut passwordlen: size_t,
                                       mut salt: *const libc::c_char,
                                       mut saltlen: size_t,
                                       mut c: libc::c_uint,
                                       mut dk: *mut libc::c_char,
                                       mut dklen: size_t) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut gch: Gc_hash = GC_MD4;
    match hash as libc::c_uint {
        2 => {
            if dklen == 0 as libc::c_int as libc::c_ulong {
                dklen = GSASL_HASH_SHA1_SIZE as libc::c_int as size_t
            }
            gch = GC_SHA1
        }
        3 => {
            if dklen == 0 as libc::c_int as libc::c_ulong {
                dklen = GSASL_HASH_SHA256_SIZE as libc::c_int as size_t
            }
            gch = GC_SHA256
        }
        _ => { return GSASL_CRYPTO_ERROR as libc::c_int }
    }
    rc =
        gc_pbkdf2_hmac(gch, password, passwordlen, salt, saltlen, c, dk,
                       dklen) as libc::c_int;
    if rc != GC_OK as libc::c_int { return GSASL_CRYPTO_ERROR as libc::c_int }
    return GSASL_OK as libc::c_int;
}
