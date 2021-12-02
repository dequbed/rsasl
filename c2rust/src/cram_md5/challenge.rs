use ::libc;
extern "C" {
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    #[no_mangle]
    fn __assert_fail(__assertion: *const libc::c_char,
                     __file: *const libc::c_char, __line: libc::c_uint,
                     __function: *const libc::c_char) -> !;
    /* Randomness. */
    #[no_mangle]
    fn gc_nonce(data: *mut libc::c_char, datalen: size_t) -> Gc_rc;
}
pub type size_t = libc::c_ulong;
pub const GC_OK: Gc_rc = 0;
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
/* Store zero terminated CRAM-MD5 challenge in output buffer.  The
   CHALLENGE buffer must be allocated by the caller, and must have
   room for CRAM_MD5_CHALLENGE_LEN characters.  Returns 0 on success,
   and -1 on randomness problems.  */
#[no_mangle]
pub unsafe extern "C" fn cram_md5_challenge(mut challenge: *mut libc::c_char)
 -> libc::c_int {
    let mut nonce: [libc::c_char; 10] = [0; 10];
    let mut i: size_t = 0;
    let mut rc: libc::c_int = 0;
    if strlen(b"<XXXXXXXXXXXXXXXXXXXX.0@localhost>\x00" as *const u8 as
                  *const libc::c_char) ==
           (35 as libc::c_int - 1 as libc::c_int) as libc::c_ulong {
    } else {
        __assert_fail(b"strlen (TEMPLATE) == CRAM_MD5_CHALLENGE_LEN - 1\x00"
                          as *const u8 as *const libc::c_char,
                      b"challenge.c\x00" as *const u8 as *const libc::c_char,
                      74 as libc::c_int as libc::c_uint,
                      (*::std::mem::transmute::<&[u8; 31],
                                                &[libc::c_char; 31]>(b"int cram_md5_challenge(char *)\x00")).as_ptr());
    }
    memcpy(challenge as *mut libc::c_void,
           b"<XXXXXXXXXXXXXXXXXXXX.0@localhost>\x00" as *const u8 as
               *const libc::c_char as *const libc::c_void,
           35 as libc::c_int as libc::c_ulong);
    rc =
        gc_nonce(nonce.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 10]>() as libc::c_ulong)
            as libc::c_int;
    if rc != GC_OK as libc::c_int { return -(1 as libc::c_int) }
    i = 0 as libc::c_int as size_t;
    while i < ::std::mem::size_of::<[libc::c_char; 10]>() as libc::c_ulong {
        *challenge.offset((1 as libc::c_int as libc::c_ulong).wrapping_add(i)
                              as isize) =
            if nonce[i as usize] as libc::c_int & 0xf as libc::c_int >
                   9 as libc::c_int {
                ('0' as i32 +
                     (nonce[i as usize] as libc::c_int & 0xf as libc::c_int))
                    - 10 as libc::c_int
            } else {
                ('0' as i32) +
                    (nonce[i as usize] as libc::c_int & 0xf as libc::c_int)
            } as libc::c_char;
        *challenge.offset((11 as libc::c_int as libc::c_ulong).wrapping_add(i)
                              as isize) =
            if nonce[i as usize] as libc::c_int >> 4 as libc::c_int &
                   0xf as libc::c_int > 9 as libc::c_int {
                ('0' as i32 +
                     (nonce[i as usize] as libc::c_int >> 4 as libc::c_int &
                          0xf as libc::c_int)) - 10 as libc::c_int
            } else {
                ('0' as i32) +
                    (nonce[i as usize] as libc::c_int >> 4 as libc::c_int &
                         0xf as libc::c_int)
            } as libc::c_char;
        i = i.wrapping_add(1)
    }
    return 0 as libc::c_int;
}
