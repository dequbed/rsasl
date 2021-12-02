use ::libc;
extern "C" {
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    fn memchr(_: *const libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    fn strnlen(__string: *const libc::c_char, __maxlen: size_t) -> size_t;
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
    fn scram_valid_client_first(cf: *mut scram_client_first) -> bool;
    fn scram_valid_server_first(sf: *mut scram_server_first) -> bool;
    fn scram_valid_client_final(cl: *mut scram_client_final) -> bool;
    fn scram_valid_server_final(sl: *mut scram_server_final) -> bool;
}
pub type size_t = libc::c_ulong;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_server_first {
    pub nonce: *mut libc::c_char,
    pub salt: *mut libc::c_char,
    pub iter: size_t,
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
pub struct scram_server_final {
    pub verifier: *mut libc::c_char,
}
#[inline]
unsafe extern "C" fn c_isalpha(mut c: libc::c_int) -> bool {
    match c {
        97 | 98 | 99 | 100 | 101 | 102 | 103 | 104 | 105 | 106 | 107 | 108 |
        109 | 110 | 111 | 112 | 113 | 114 | 115 | 116 | 117 | 118 | 119 | 120
        | 121 | 122 | 65 | 66 | 67 | 68 | 69 | 70 | 71 | 72 | 73 | 74 | 75 |
        76 | 77 | 78 | 79 | 80 | 81 | 82 | 83 | 84 | 85 | 86 | 87 | 88 | 89 |
        90 => {
            return 1 as libc::c_int != 0
        }
        _ => { return 0 as libc::c_int != 0 }
    };
}
/* parser.c --- SCRAM parser.
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
/* Get malloc, free. */
/* Get memcpy, strlen. */
/* Get validator. */
/* Get c_isalpha. */
unsafe extern "C" fn unescape(mut str: *const libc::c_char, mut len: size_t)
 -> *mut libc::c_char {
    let mut out: *mut libc::c_char =
        malloc(len.wrapping_add(1 as libc::c_int as libc::c_ulong)) as
            *mut libc::c_char;
    let mut p: *mut libc::c_char = out;
    if out.is_null() { return 0 as *mut libc::c_char }
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
        } else {
            let fresh2 = p;
            p = p.offset(1);
            *fresh2 = *str;
            str = str.offset(1);
            len = len.wrapping_sub(1)
        }
    }
    *p = '\u{0}' as i32 as libc::c_char;
    return out;
}
#[no_mangle]
pub unsafe extern "C" fn scram_parse_client_first(mut str:
                                                      *const libc::c_char,
                                                  mut len: size_t,
                                                  mut cf:
                                                      *mut scram_client_first)
 -> libc::c_int {
    /* Minimum client first string is 'n,,n=a,r=b'. */
    if strnlen(str, len) < 10 as libc::c_int as libc::c_ulong {
        return -(1 as libc::c_int)
    }
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != 'n' as i32 &&
               *str as libc::c_int != 'y' as i32 &&
               *str as libc::c_int != 'p' as i32 {
        return -(1 as libc::c_int)
    }
    (*cf).cbflag = *str;
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if (*cf).cbflag as libc::c_int == 'p' as i32 {
        let mut p: *const libc::c_char = 0 as *const libc::c_char;
        if len == 0 as libc::c_int as libc::c_ulong ||
               *str as libc::c_int != '=' as i32 {
            return -(1 as libc::c_int)
        }
        str = str.offset(1);
        len = len.wrapping_sub(1);
        p =
            memchr(str as *const libc::c_void, ',' as i32, len) as
                *const libc::c_char;
        if p.is_null() { return -(1 as libc::c_int) }
        (*cf).cbname =
            malloc((p.offset_from(str) as libc::c_long +
                        1 as libc::c_int as libc::c_long) as libc::c_ulong) as
                *mut libc::c_char;
        if (*cf).cbname.is_null() { return -(1 as libc::c_int) }
        memcpy((*cf).cbname as *mut libc::c_void, str as *const libc::c_void,
               p.offset_from(str) as libc::c_long as libc::c_ulong);
        *(*cf).cbname.offset(p.offset_from(str) as libc::c_long as
                                 isize) = '\u{0}' as i32 as libc::c_char;
        len =
            (len as
                 libc::c_ulong).wrapping_sub(p.offset_from(str) as
                                                 libc::c_long as
                                                 libc::c_ulong) as size_t as
                size_t;
        str = str.offset(p.offset_from(str) as libc::c_long as isize)
    }
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 as libc::c_int as libc::c_ulong { return -(1 as libc::c_int) }
    if *str as libc::c_int == 'a' as i32 {
        let mut p_0: *const libc::c_char = 0 as *const libc::c_char;
        let mut l: size_t = 0;
        str = str.offset(1);
        len = len.wrapping_sub(1);
        if len == 0 as libc::c_int as libc::c_ulong ||
               *str as libc::c_int != '=' as i32 {
            return -(1 as libc::c_int)
        }
        str = str.offset(1);
        len = len.wrapping_sub(1);
        p_0 =
            memchr(str as *const libc::c_void, ',' as i32, len) as
                *const libc::c_char;
        if p_0.is_null() { return -(1 as libc::c_int) }
        l = p_0.offset_from(str) as libc::c_long as size_t;
        if len < l { return -(1 as libc::c_int) }
        (*cf).authzid = unescape(str, l);
        if (*cf).authzid.is_null() { return -(1 as libc::c_int) }
        str = p_0;
        len = (len as libc::c_ulong).wrapping_sub(l) as size_t as size_t
    }
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != 'n' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    let mut p_1: *const libc::c_char = 0 as *const libc::c_char;
    let mut l_0: size_t = 0;
    p_1 =
        memchr(str as *const libc::c_void, ',' as i32, len) as
            *const libc::c_char;
    if p_1.is_null() { return -(1 as libc::c_int) }
    l_0 = p_1.offset_from(str) as libc::c_long as size_t;
    if len < l_0 { return -(1 as libc::c_int) }
    (*cf).username = unescape(str, l_0);
    if (*cf).username.is_null() { return -(1 as libc::c_int) }
    str = p_1;
    len = (len as libc::c_ulong).wrapping_sub(l_0) as size_t as size_t;
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != 'r' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    let mut p_2: *const libc::c_char = 0 as *const libc::c_char;
    let mut l_1: size_t = 0;
    p_2 =
        memchr(str as *const libc::c_void, ',' as i32, len) as
            *const libc::c_char;
    if p_2.is_null() { p_2 = str.offset(len as isize) }
    if p_2.is_null() { return -(1 as libc::c_int) }
    l_1 = p_2.offset_from(str) as libc::c_long as size_t;
    if len < l_1 { return -(1 as libc::c_int) }
    (*cf).client_nonce =
        malloc(l_1.wrapping_add(1 as libc::c_int as libc::c_ulong)) as
            *mut libc::c_char;
    if (*cf).client_nonce.is_null() { return -(1 as libc::c_int) }
    memcpy((*cf).client_nonce as *mut libc::c_void,
           str as *const libc::c_void, l_1);
    *(*cf).client_nonce.offset(l_1 as isize) = '\u{0}' as i32 as libc::c_char;
    str = p_2;
    len = (len as libc::c_ulong).wrapping_sub(l_1) as size_t as size_t;
    /* FIXME check that any extension fields follow valid syntax. */
    if !scram_valid_client_first(cf) { return -(1 as libc::c_int) }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn scram_parse_server_first(mut str:
                                                      *const libc::c_char,
                                                  mut len: size_t,
                                                  mut sf:
                                                      *mut scram_server_first)
 -> libc::c_int {
    /* Minimum server first string is 'r=ab,s=biws,i=1'. */
    if strnlen(str, len) < 15 as libc::c_int as libc::c_ulong {
        return -(1 as libc::c_int)
    }
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != 'r' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    let mut l: size_t = 0;
    p =
        memchr(str as *const libc::c_void, ',' as i32, len) as
            *const libc::c_char;
    if p.is_null() { return -(1 as libc::c_int) }
    l = p.offset_from(str) as libc::c_long as size_t;
    if len < l { return -(1 as libc::c_int) }
    (*sf).nonce =
        malloc(l.wrapping_add(1 as libc::c_int as libc::c_ulong)) as
            *mut libc::c_char;
    if (*sf).nonce.is_null() { return -(1 as libc::c_int) }
    memcpy((*sf).nonce as *mut libc::c_void, str as *const libc::c_void, l);
    *(*sf).nonce.offset(l as isize) = '\u{0}' as i32 as libc::c_char;
    str = p;
    len = (len as libc::c_ulong).wrapping_sub(l) as size_t as size_t;
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != 's' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    let mut p_0: *const libc::c_char = 0 as *const libc::c_char;
    let mut l_0: size_t = 0;
    p_0 =
        memchr(str as *const libc::c_void, ',' as i32, len) as
            *const libc::c_char;
    if p_0.is_null() { return -(1 as libc::c_int) }
    l_0 = p_0.offset_from(str) as libc::c_long as size_t;
    if len < l_0 { return -(1 as libc::c_int) }
    (*sf).salt =
        malloc(l_0.wrapping_add(1 as libc::c_int as libc::c_ulong)) as
            *mut libc::c_char;
    if (*sf).salt.is_null() { return -(1 as libc::c_int) }
    memcpy((*sf).salt as *mut libc::c_void, str as *const libc::c_void, l_0);
    *(*sf).salt.offset(l_0 as isize) = '\u{0}' as i32 as libc::c_char;
    str = p_0;
    len = (len as libc::c_ulong).wrapping_sub(l_0) as size_t as size_t;
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != 'i' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    (*sf).iter = 0 as libc::c_int as size_t;
    while len > 0 as libc::c_int as libc::c_ulong &&
              *str as libc::c_int >= '0' as i32 &&
              *str as libc::c_int <= '9' as i32 {
        let mut last_iter: size_t = (*sf).iter;
        (*sf).iter =
            (*sf).iter.wrapping_mul(10 as libc::c_int as
                                        libc::c_ulong).wrapping_add((*str as
                                                                         libc::c_int
                                                                         -
                                                                         '0'
                                                                             as
                                                                             i32)
                                                                        as
                                                                        libc::c_ulong);
        /* Protect against wrap arounds. */
        if (*sf).iter < last_iter { return -(1 as libc::c_int) }
        str = str.offset(1);
        len = len.wrapping_sub(1)
    }
    if len > 0 as libc::c_int as libc::c_ulong &&
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    /* FIXME check that any extension fields follow valid syntax. */
    if !scram_valid_server_first(sf) { return -(1 as libc::c_int) }
    return 0 as libc::c_int;
}
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
pub unsafe extern "C" fn scram_parse_client_final(mut str:
                                                      *const libc::c_char,
                                                  mut len: size_t,
                                                  mut cl:
                                                      *mut scram_client_final)
 -> libc::c_int {
    /* Minimum client final string is 'c=biws,r=ab,p=ab=='. */
    if strnlen(str, len) < 18 as libc::c_int as libc::c_ulong {
        return -(1 as libc::c_int)
    }
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != 'c' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    let mut l: size_t = 0;
    p =
        memchr(str as *const libc::c_void, ',' as i32, len) as
            *const libc::c_char;
    if p.is_null() { return -(1 as libc::c_int) }
    l = p.offset_from(str) as libc::c_long as size_t;
    if len < l { return -(1 as libc::c_int) }
    (*cl).cbind =
        malloc(l.wrapping_add(1 as libc::c_int as libc::c_ulong)) as
            *mut libc::c_char;
    if (*cl).cbind.is_null() { return -(1 as libc::c_int) }
    memcpy((*cl).cbind as *mut libc::c_void, str as *const libc::c_void, l);
    *(*cl).cbind.offset(l as isize) = '\u{0}' as i32 as libc::c_char;
    str = p;
    len = (len as libc::c_ulong).wrapping_sub(l) as size_t as size_t;
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != 'r' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    let mut p_0: *const libc::c_char = 0 as *const libc::c_char;
    let mut l_0: size_t = 0;
    p_0 =
        memchr(str as *const libc::c_void, ',' as i32, len) as
            *const libc::c_char;
    if p_0.is_null() { return -(1 as libc::c_int) }
    l_0 = p_0.offset_from(str) as libc::c_long as size_t;
    if len < l_0 { return -(1 as libc::c_int) }
    (*cl).nonce =
        malloc(l_0.wrapping_add(1 as libc::c_int as libc::c_ulong)) as
            *mut libc::c_char;
    if (*cl).nonce.is_null() { return -(1 as libc::c_int) }
    memcpy((*cl).nonce as *mut libc::c_void, str as *const libc::c_void, l_0);
    *(*cl).nonce.offset(l_0 as isize) = '\u{0}' as i32 as libc::c_char;
    str = p_0;
    len = (len as libc::c_ulong).wrapping_sub(l_0) as size_t as size_t;
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    /* Ignore extensions. */
    while len > 0 as libc::c_int as libc::c_ulong &&
              c_isalpha(*str as libc::c_int) as libc::c_int != 0 &&
              *str as libc::c_int != 'p' as i32 {
        let mut p_1: *const libc::c_char = 0 as *const libc::c_char;
        let mut l_1: size_t = 0;
        str = str.offset(1);
        len = len.wrapping_sub(1);
        if len == 0 as libc::c_int as libc::c_ulong ||
               *str as libc::c_int != '=' as i32 {
            return -(1 as libc::c_int)
        }
        str = str.offset(1);
        len = len.wrapping_sub(1);
        p_1 =
            memchr(str as *const libc::c_void, ',' as i32, len) as
                *const libc::c_char;
        if p_1.is_null() { return -(1 as libc::c_int) }
        p_1 = p_1.offset(1);
        l_1 = p_1.offset_from(str) as libc::c_long as size_t;
        if len < l_1 { return -(1 as libc::c_int) }
        str = p_1;
        len = (len as libc::c_ulong).wrapping_sub(l_1) as size_t as size_t
    }
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != 'p' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    /* Sanity check proof. */
    if !memchr(str as *const libc::c_void, '\u{0}' as i32, len).is_null() {
        return -(1 as libc::c_int)
    }
    (*cl).proof =
        malloc(len.wrapping_add(1 as libc::c_int as libc::c_ulong)) as
            *mut libc::c_char;
    if (*cl).proof.is_null() { return -(1 as libc::c_int) }
    memcpy((*cl).proof as *mut libc::c_void, str as *const libc::c_void, len);
    *(*cl).proof.offset(len as isize) = '\u{0}' as i32 as libc::c_char;
    if !scram_valid_client_final(cl) { return -(1 as libc::c_int) }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn scram_parse_server_final(mut str:
                                                      *const libc::c_char,
                                                  mut len: size_t,
                                                  mut sl:
                                                      *mut scram_server_final)
 -> libc::c_int {
    /* Minimum client final string is 'v=ab=='. */
    if strnlen(str, len) < 6 as libc::c_int as libc::c_ulong {
        return -(1 as libc::c_int)
    }
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != 'v' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 as libc::c_int as libc::c_ulong ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    /* Sanity check proof. */
    if !memchr(str as *const libc::c_void, '\u{0}' as i32, len).is_null() {
        return -(1 as libc::c_int)
    }
    (*sl).verifier =
        malloc(len.wrapping_add(1 as libc::c_int as libc::c_ulong)) as
            *mut libc::c_char;
    if (*sl).verifier.is_null() { return -(1 as libc::c_int) }
    memcpy((*sl).verifier as *mut libc::c_void, str as *const libc::c_void,
           len);
    *(*sl).verifier.offset(len as isize) = '\u{0}' as i32 as libc::c_char;
    if !scram_valid_server_final(sl) { return -(1 as libc::c_int) }
    return 0 as libc::c_int;
}
