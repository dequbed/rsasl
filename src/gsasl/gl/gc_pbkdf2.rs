use ::libc;
use libc::{malloc, memcpy, memset, size_t};
use crate::gsasl::gc::{GC_INVALID_HASH, GC_MALLOC_ERROR, GC_OK, GC_PKCS5_DERIVED_KEY_TOO_LONG, GC_PKCS5_INVALID_DERIVED_KEY_LENGTH, GC_PKCS5_INVALID_ITERATION_COUNT, Gc_rc};
use crate::gsasl::gl::free::rpl_free;
use crate::gsasl::gl::gc_gnulib::{Gc_hash, gc_hmac_sha1, gc_hmac_sha256};

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
/* gc-pbkdf2.c --- Password-Based Key Derivation Function a'la PKCS#5
   Copyright (C) 2002-2006, 2009-2021 Free Software Foundation, Inc.

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
/* Written by Simon Josefsson. */
pub type gc_prf_func
    =
    Option<unsafe fn(_: *const libc::c_void, _: size_t,
                                _: *const libc::c_void, _: size_t,
                                _: *mut libc::c_char) -> Gc_rc>;
unsafe fn gc_pbkdf2_prf(mut prf: gc_prf_func, mut hLen: size_t,
                                   mut P: *const libc::c_char,
                                   mut Plen: size_t,
                                   mut S: *const libc::c_char,
                                   mut Slen: size_t, mut c: libc::c_uint,
                                   mut DK: *mut libc::c_char,
                                   mut dkLen: size_t) -> Gc_rc {
    let mut U: [libc::c_char; 64] = [0; 64];
    let mut T: [libc::c_char; 64] = [0; 64];
    let mut u: libc::c_uint = 0;
    let mut l: libc::c_uint = 0;
    let mut r: libc::c_uint = 0;
    let mut i: libc::c_uint = 0;
    let mut k: libc::c_uint = 0;
    let mut rc: libc::c_int = 0;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmplen: size_t =
        Slen.wrapping_add(4);
    if c == 0 as libc::c_int as libc::c_uint {
        return GC_PKCS5_INVALID_ITERATION_COUNT
    }
    if dkLen == 0 {
        return GC_PKCS5_INVALID_DERIVED_KEY_LENGTH
    }
    if dkLen > 4294967295 {
        return GC_PKCS5_DERIVED_KEY_TOO_LONG
    }
    l = dkLen.wrapping_sub(1).wrapping_div(hLen).wrapping_add(1) as libc::c_uint;
    r = dkLen.wrapping_sub((l.wrapping_sub(1).wrapping_mul(hLen as u32)) as size_t)
        as libc::c_uint;
    tmp = malloc(tmplen) as *mut libc::c_char;
    if tmp.is_null() { return GC_MALLOC_ERROR }
    memcpy(tmp as *mut libc::c_void, S as *const libc::c_void, Slen);
    i = 1 as libc::c_int as libc::c_uint;
    while i <= l {
        memset(T.as_mut_ptr() as *mut libc::c_void, 0 as libc::c_int, hLen);
        u = 1 as libc::c_int as libc::c_uint;
        while u <= c {
            if u == 1 as libc::c_int as libc::c_uint {
                *tmp.offset(Slen.wrapping_add(0) as isize) =
                    ((i & 0xff000000 as libc::c_uint) >> 24 as libc::c_int) as
                        libc::c_char;
                *tmp.offset(Slen.wrapping_add(1) as isize) =
                    ((i & 0xff0000 as libc::c_int as libc::c_uint) >>
                         16 as libc::c_int) as libc::c_char;
                *tmp.offset(Slen.wrapping_add(2) as isize) =
                    ((i & 0xff00 as libc::c_int as libc::c_uint) >>
                         8 as libc::c_int) as libc::c_char;
                *tmp.offset(Slen.wrapping_add(3) as isize) =
                    ((i & 0xff as libc::c_int as libc::c_uint) >>
                         0 as libc::c_int) as libc::c_char;
                rc =
                    prf.expect("non-null function pointer")(P as
                                                                *const libc::c_void,
                                                            Plen,
                                                            tmp as
                                                                *const libc::c_void,
                                                            tmplen,
                                                            U.as_mut_ptr()) as
                        libc::c_int
            } else {
                rc =
                    prf.expect("non-null function pointer")(P as
                                                                *const libc::c_void,
                                                            Plen,
                                                            U.as_mut_ptr() as
                                                                *const libc::c_void,
                                                            hLen,
                                                            U.as_mut_ptr()) as
                        libc::c_int
            }
            if rc != GC_OK as libc::c_int {
                rpl_free(tmp as *mut libc::c_void);
                return rc as Gc_rc
            }
            k = 0 as libc::c_int as libc::c_uint;
            while (k as size_t) < hLen {
                T[k as usize] =
                    (T[k as usize] as libc::c_int ^
                         U[k as usize] as libc::c_int) as libc::c_char;
                k = k.wrapping_add(1)
            }
            u = u.wrapping_add(1)
        }
        memcpy(DK.offset((i.wrapping_sub(1 as libc::c_int as libc::c_uint) as
                              size_t).wrapping_mul(hLen) as isize) as
                   *mut libc::c_void, T.as_mut_ptr() as *const libc::c_void,
               if i == l { r as size_t } else { hLen });
        i = i.wrapping_add(1)
    }
    rpl_free(tmp as *mut libc::c_void);
    return GC_OK;
}
/* Derive cryptographic keys using PKCS#5 PBKDF2 (RFC 2898) from a
   password P of length PLEN, with salt S of length SLEN, placing the
   result in pre-allocated buffer DK of length DKLEN.  The PRF is hard
   coded to be HMAC with HASH.  An iteration count is specified in C
   (> 0), where a larger value means this function take more time
   (typical iteration counts are 1000-20000).  This function
   "stretches" the key to be exactly dkLen bytes long.  GC_OK is
   returned on success, otherwise a Gc_rc error code is returned.  */
pub unsafe fn gc_pbkdf2_hmac(mut hash: Gc_hash,
                                        mut P: *const libc::c_char,
                                        mut Plen: size_t,
                                        mut S: *const libc::c_char,
                                        mut Slen: size_t, mut c: libc::c_uint,
                                        mut DK: *mut libc::c_char,
                                        mut dkLen: size_t) -> Gc_rc {
    let mut prf: gc_prf_func = None;
    let mut hLen: size_t = 0;
    match hash as libc::c_uint {
        2 => {
            prf =
                Some(gc_hmac_sha1);
            hLen = 20 as libc::c_int as size_t
        }
        5 => {
            prf =
                Some(gc_hmac_sha256);
            hLen = 32 as libc::c_int as size_t
        }
        _ => { return GC_INVALID_HASH }
    }
    return gc_pbkdf2_prf(prf, hLen, P, Plen, S, Slen, c, DK, dkLen);
}
