use ::libc;
use libc::{malloc, size_t, strdup, strlen};

/* server.c --- DIGEST-MD5 mechanism from RFC 2831, server side.
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
/* Get specification. */
/* C89 compliant way to cast 'char' to 'unsigned char'. */
#[inline]
unsafe fn to_uchar(ch: libc::c_char) -> libc::c_uchar {
    return ch as libc::c_uchar;
}
/* nonascii.h --- Prototypes for UTF-8 vs Latin-1 conversion for DIGEST-MD5
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
#[no_mangle]
pub unsafe fn latin1toutf8(str: *const libc::c_char) -> *mut libc::c_char {
    let p: *mut libc::c_char =
        malloc((2 as size_t).wrapping_mul(strlen(str)).wrapping_add(1)) as *mut libc::c_char;
    if !p.is_null() {
        let mut i: size_t = 0;
        let mut j: size_t = 0 as libc::c_int as size_t;
        i = 0 as libc::c_int as size_t;
        while *str.offset(i as isize) != 0 {
            if (to_uchar(*str.offset(i as isize)) as libc::c_int) < 0x80 as libc::c_int {
                let fresh0 = j;
                j = j.wrapping_add(1);
                *p.offset(fresh0 as isize) = *str.offset(i as isize)
            } else if (to_uchar(*str.offset(i as isize)) as libc::c_int) < 0xc0 as libc::c_int {
                let fresh1 = j;
                j = j.wrapping_add(1);
                *p.offset(fresh1 as isize) = 0xc2 as libc::c_int as libc::c_uchar as libc::c_char;
                let fresh2 = j;
                j = j.wrapping_add(1);
                *p.offset(fresh2 as isize) = *str.offset(i as isize)
            } else {
                let fresh3 = j;
                j = j.wrapping_add(1);
                *p.offset(fresh3 as isize) = 0xc3 as libc::c_int as libc::c_uchar as libc::c_char;
                let fresh4 = j;
                j = j.wrapping_add(1);
                *p.offset(fresh4 as isize) =
                    (*str.offset(i as isize) as libc::c_int - 64 as libc::c_int) as libc::c_char
            }
            i = i.wrapping_add(1)
        }
        *p.offset(j as isize) = 0 as libc::c_int as libc::c_char
    }
    return p;
}
#[no_mangle]
pub unsafe fn utf8tolatin1ifpossible(passwd: *const libc::c_char) -> *mut libc::c_char {
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while *passwd.offset(i as isize) != 0 {
        if to_uchar(*passwd.offset(i as isize)) as libc::c_int > 0x7f as libc::c_int {
            if (to_uchar(*passwd.offset(i as isize)) as libc::c_int) < 0xc0 as libc::c_int
                || to_uchar(*passwd.offset(i as isize)) as libc::c_int > 0xc3 as libc::c_int
            {
                return strdup(passwd);
            }
            i = i.wrapping_add(1);
            if (to_uchar(*passwd.offset(i as isize)) as libc::c_int) < 0x80 as libc::c_int
                || to_uchar(*passwd.offset(i as isize)) as libc::c_int > 0xbf as libc::c_int
            {
                return strdup(passwd);
            }
        }
        i = i.wrapping_add(1)
    }
    p = malloc(strlen(passwd).wrapping_add(1)) as *mut libc::c_char;
    if !p.is_null() {
        let mut j: size_t = 0 as libc::c_int as size_t;
        i = 0 as libc::c_int as size_t;
        while *passwd.offset(i as isize) != 0 {
            if to_uchar(*passwd.offset(i as isize)) as libc::c_int > 0x7f as libc::c_int {
                /* p[i+1] can't be zero here */
                let fresh5 = j;
                j = j.wrapping_add(1);
                *p.offset(fresh5 as isize) =
                    ((to_uchar(*passwd.offset(i as isize)) as libc::c_int & 0x3 as libc::c_int)
                        << 6 as libc::c_int
                        | to_uchar(*passwd.offset(i.wrapping_add(1) as isize)) as libc::c_int
                            & 0x3f as libc::c_int) as libc::c_char;
                i = i.wrapping_add(1)
            } else {
                let fresh6 = j;
                j = j.wrapping_add(1);
                *p.offset(fresh6 as isize) = *passwd.offset(i as isize)
            }
            i = i.wrapping_add(1)
        }
        *p.offset(j as isize) = 0 as libc::c_int as libc::c_char
    }
    return p;
}
