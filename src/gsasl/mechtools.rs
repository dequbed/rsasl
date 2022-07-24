use crate::gsasl::consts::{
    GSASL_CRYPTO_ERROR, GSASL_MALLOC_ERROR, GSASL_MECHANISM_PARSE_ERROR, GSASL_OK,
};
use crate::gsasl::gc::GC_OK;
use crate::gsasl::gl::free::rpl_free;
use ::libc;
use libc::{malloc, memchr, memcpy, size_t, strchr, strlen, strncmp};

extern "C" {
    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char, _: ...) -> libc::c_int;
}

pub type Gsasl_hash = libc::c_uint;
pub const GSASL_HASH_SHA256: Gsasl_hash = 3;
pub const GSASL_HASH_SHA1: Gsasl_hash = 2;
pub type C2RustUnnamed_0 = libc::c_uint;
pub const GSASL_HASH_MAX_SIZE: C2RustUnnamed_0 = 32;
pub const GSASL_HASH_SHA256_SIZE: C2RustUnnamed_0 = 32;
pub const GSASL_HASH_SHA1_SIZE: C2RustUnnamed_0 = 20;
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
unsafe fn unescape_authzid(
    mut str: *const libc::c_char,
    mut len: size_t,
    mut authzid: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    if !memchr(str as *const libc::c_void, ',' as i32, len).is_null() {
        return GSASL_MECHANISM_PARSE_ERROR as libc::c_int;
    }
    *authzid = malloc(len.wrapping_add(1)) as *mut libc::c_char;

    p = *authzid;
    if p.is_null() {
        return GSASL_MALLOC_ERROR as libc::c_int;
    }
    while len > 0 && *str as libc::c_int != 0 {
        if len >= 3
            && *str.offset(0 as libc::c_int as isize) as libc::c_int == '=' as i32
            && *str.offset(1 as libc::c_int as isize) as libc::c_int == '2' as i32
            && *str.offset(2 as libc::c_int as isize) as libc::c_int == 'C' as i32
        {
            let fresh0 = p;
            p = p.offset(1);
            *fresh0 = ',' as i32 as libc::c_char;
            str = str.offset(3 as libc::c_int as isize);
            len = (len as libc::c_ulong).wrapping_sub(3 as libc::c_int as libc::c_ulong) as size_t
                as size_t
        } else if len >= 3
            && *str.offset(0 as libc::c_int as isize) as libc::c_int == '=' as i32
            && *str.offset(1 as libc::c_int as isize) as libc::c_int == '3' as i32
            && *str.offset(2 as libc::c_int as isize) as libc::c_int == 'D' as i32
        {
            let fresh1 = p;
            p = p.offset(1);
            *fresh1 = '=' as i32 as libc::c_char;
            str = str.offset(3 as libc::c_int as isize);
            len = (len as libc::c_ulong).wrapping_sub(3 as libc::c_int as libc::c_ulong) as size_t
                as size_t
        } else if *str.offset(0 as libc::c_int as isize) as libc::c_int == '=' as i32 {
            rpl_free(*authzid as *mut libc::c_void);
            *authzid = 0 as *mut libc::c_char;
            return GSASL_MECHANISM_PARSE_ERROR as libc::c_int;
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

pub unsafe fn _gsasl_parse_gs2_header(
    mut data: *const libc::c_char,
    mut len: size_t,
    mut authzid: *mut *mut libc::c_char,
    mut headerlen: *mut size_t,
) -> libc::c_int {
    let mut authzid_endptr: *mut libc::c_char = 0 as *mut libc::c_char;
    if len < 3 {
        return GSASL_MECHANISM_PARSE_ERROR as libc::c_int;
    }
    if strncmp(data, b"n,,\x00" as *const u8 as *const libc::c_char, 3) == 0 {
        *headerlen = 3 as libc::c_int as size_t;
        *authzid = 0 as *mut libc::c_char
    } else if strncmp(data, b"n,a=\x00" as *const u8 as *const libc::c_char, 4) == 0 && {
        authzid_endptr = memchr(
            data.offset(4) as *const libc::c_void,
            ',' as i32,
            len.wrapping_sub(4),
        ) as *mut libc::c_char;
        !authzid_endptr.is_null()
    } {
        let mut res: libc::c_int = 0;
        if authzid_endptr.is_null() {
            return GSASL_MECHANISM_PARSE_ERROR as libc::c_int;
        }
        res = unescape_authzid(
            data.offset(4 as libc::c_int as isize),
            authzid_endptr.offset_from(data.offset(4)) as libc::c_long as size_t,
            authzid,
        );
        if res != GSASL_OK as libc::c_int {
            return res;
        }
        *headerlen = (authzid_endptr.offset_from(data) + 1) as size_t
    } else {
        return GSASL_MECHANISM_PARSE_ERROR as libc::c_int;
    }
    return GSASL_OK as libc::c_int;
}
/* Return newly allocated copy of STR with all occurrences of ','
replaced with =2C and '=' with '=3D', or return NULL on memory
allocation errors.  */
unsafe fn escape_authzid(mut str: *const libc::c_char) -> *mut libc::c_char {
    let mut out: *mut libc::c_char =
        malloc(strlen(str).wrapping_mul(3).wrapping_add(1)) as *mut libc::c_char;

    let mut p: *mut libc::c_char = out;
    if out.is_null() {
        return 0 as *mut libc::c_char;
    }
    while *str != 0 {
        if *str as libc::c_int == ',' as i32 {
            memcpy(
                p as *mut libc::c_void,
                b"=2C\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
                3,
            );
            p = p.offset(3 as libc::c_int as isize)
        } else if *str as libc::c_int == '=' as i32 {
            memcpy(
                p as *mut libc::c_void,
                b"=3D\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
                3,
            );
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
/* Generate a newly allocated GS2 header, escaping authzid
appropriately, and appending EXTRA. */

pub unsafe fn _gsasl_gs2_generate_header(
    mut nonstd: bool,
    mut cbflag: libc::c_char,
    mut cbname: *const libc::c_char,
    mut authzid: *const libc::c_char,
    mut extralen: size_t,
    mut extra: *const libc::c_char,
    mut gs2h: *mut *mut libc::c_char,
    mut gs2hlen: *mut size_t,
) -> libc::c_int {
    let mut elen: libc::c_int = extralen as libc::c_int;
    let mut gs2cbflag: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: libc::c_int = 0;
    if cbflag as libc::c_int == 'p' as i32 {
        len = asprintf(
            &mut gs2cbflag as *mut *mut libc::c_char,
            b"p=%s\x00" as *const u8 as *const libc::c_char,
            cbname,
        )
    } else if cbflag as libc::c_int == 'n' as i32 {
        len = asprintf(
            &mut gs2cbflag as *mut *mut libc::c_char,
            b"n\x00" as *const u8 as *const libc::c_char,
        )
    } else if cbflag as libc::c_int == 'y' as i32 {
        len = asprintf(
            &mut gs2cbflag as *mut *mut libc::c_char,
            b"y\x00" as *const u8 as *const libc::c_char,
        )
    } else {
        /* internal caller error */
        return GSASL_MECHANISM_PARSE_ERROR as libc::c_int;
    }
    if len <= 0 as libc::c_int || gs2cbflag.is_null() {
        return GSASL_MALLOC_ERROR as libc::c_int;
    }
    if !authzid.is_null() {
        let mut escaped_authzid: *mut libc::c_char = escape_authzid(authzid);
        if escaped_authzid.is_null() {
            rpl_free(gs2cbflag as *mut libc::c_void);
            return GSASL_MALLOC_ERROR as libc::c_int;
        }
        len = asprintf(
            gs2h,
            b"%s%s,a=%s,%.*s\x00" as *const u8 as *const libc::c_char,
            if nonstd as libc::c_int != 0 {
                b"F,\x00" as *const u8 as *const libc::c_char
            } else {
                b"\x00" as *const u8 as *const libc::c_char
            },
            gs2cbflag,
            escaped_authzid,
            elen,
            extra,
        );
        rpl_free(escaped_authzid as *mut libc::c_void);
    } else {
        len = asprintf(
            gs2h,
            b"%s%s,,%.*s\x00" as *const u8 as *const libc::c_char,
            if nonstd as libc::c_int != 0 {
                b"F,\x00" as *const u8 as *const libc::c_char
            } else {
                b"\x00" as *const u8 as *const libc::c_char
            },
            gs2cbflag,
            elen,
            extra,
        )
    }
    rpl_free(gs2cbflag as *mut libc::c_void);
    if len <= 0 as libc::c_int || gs2h.is_null() {
        return GSASL_MALLOC_ERROR as libc::c_int;
    }
    *gs2hlen = len as size_t;
    return GSASL_OK as libc::c_int;
}
/* Hex encode binary octet array IN of INLEN length, putting the hex
encoded string in OUT which must have room for the data and
terminating zero, i.e., 2*INLEN+1. */

pub unsafe fn _gsasl_hex_encode(
    mut in_0: *const libc::c_char,
    mut inlen: size_t,
    mut out: *mut libc::c_char,
) {
    let mut i: size_t = 0;
    let mut p: *const libc::c_char = in_0;
    i = 0 as libc::c_int as size_t;
    while i < inlen.wrapping_mul(2) {
        let fresh3 = p;
        p = p.offset(1);
        let mut c: libc::c_uchar = *fresh3 as libc::c_uchar;
        let fresh4 = i;
        i = i.wrapping_add(1);
        *out.offset(fresh4 as isize) =
            (*::std::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"0123456789abcdef\x00"))
                [(c as libc::c_int >> 4 as libc::c_int) as usize];
        let fresh5 = i;
        i = i.wrapping_add(1);
        *out.offset(fresh5 as isize) =
            (*::std::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"0123456789abcdef\x00"))
                [(c as libc::c_int & 0xf as libc::c_int) as usize]
    }
    *out.offset(i as isize) = '\u{0}' as i32 as libc::c_char;
}

unsafe fn hexdigit_to_char(mut hexdigit: libc::c_char) -> libc::c_char {
    if hexdigit as libc::c_int >= '0' as i32 && hexdigit as libc::c_int <= '9' as i32 {
        return (hexdigit as libc::c_int - '0' as i32) as libc::c_char;
    }
    if hexdigit as libc::c_int >= 'a' as i32 && hexdigit as libc::c_int <= 'f' as i32 {
        return (hexdigit as libc::c_int - 'a' as i32 + 10 as libc::c_int) as libc::c_char;
    }
    return 0 as libc::c_int as libc::c_char;
}

unsafe fn hex_to_char(mut u: libc::c_char, mut l: libc::c_char) -> libc::c_char {
    return (hexdigit_to_char(u) as libc::c_uchar as libc::c_int * 16 as libc::c_int
        + hexdigit_to_char(l) as libc::c_int) as libc::c_char;
}

/* Hex decode string HEXSTR containing only hex "0-9A-F" characters
into binary buffer BIN which must have room for data, i.e., strlen
(hexstr)/2. */

pub unsafe fn _gsasl_hex_decode(mut hexstr: *const libc::c_char, mut bin: *mut libc::c_char) {
    while *hexstr != 0 {
        *bin = hex_to_char(
            *hexstr.offset(0 as libc::c_int as isize),
            *hexstr.offset(1 as libc::c_int as isize),
        );
        hexstr = hexstr.offset(2 as libc::c_int as isize);
        bin = bin.offset(1)
    }
}