use ::libc;
extern "C" {
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
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void,
              _: libc::c_ulong) -> libc::c_int;
    #[no_mangle]
    fn gc_hmac_md5(key: *const libc::c_void, keylen: size_t,
                   in_0: *const libc::c_void, inlen: size_t,
                   resbuf: *mut libc::c_char) -> Gc_rc;
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
pub unsafe extern "C" fn digest_md5_encode(mut input: *const libc::c_char,
                                           mut input_len: size_t,
                                           mut output: *mut *mut libc::c_char,
                                           mut output_len: *mut size_t,
                                           mut qop: digest_md5_qop,
                                           mut sendseqnum: libc::c_ulong,
                                           mut key: *mut libc::c_char)
 -> libc::c_int {
    let mut res: libc::c_int = 0;
    if qop as libc::c_uint &
           DIGEST_MD5_QOP_AUTH_CONF as libc::c_int as libc::c_uint != 0 {
        return -(1 as libc::c_int)
    } else {
        if qop as libc::c_uint &
               DIGEST_MD5_QOP_AUTH_INT as libc::c_int as libc::c_uint != 0 {
            let mut seqnumin: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut hash: [libc::c_char; 16] = [0; 16];
            let mut len: size_t = 0;
            seqnumin =
                malloc((4 as libc::c_int as
                            libc::c_ulong).wrapping_add(input_len)) as
                    *mut libc::c_char;
            if seqnumin.is_null() { return -(1 as libc::c_int) }
            *seqnumin.offset(0 as libc::c_int as isize) =
                (sendseqnum >> 24 as libc::c_int &
                     0xff as libc::c_int as libc::c_ulong) as libc::c_char;
            *seqnumin.offset(1 as libc::c_int as isize) =
                (sendseqnum >> 16 as libc::c_int &
                     0xff as libc::c_int as libc::c_ulong) as libc::c_char;
            *seqnumin.offset(2 as libc::c_int as isize) =
                (sendseqnum >> 8 as libc::c_int &
                     0xff as libc::c_int as libc::c_ulong) as libc::c_char;
            *seqnumin.offset(3 as libc::c_int as isize) =
                (sendseqnum & 0xff as libc::c_int as libc::c_ulong) as
                    libc::c_char;
            memcpy(seqnumin.offset(4 as libc::c_int as isize) as
                       *mut libc::c_void, input as *const libc::c_void,
                   input_len);
            res =
                gc_hmac_md5(key as *const libc::c_void,
                            16 as libc::c_int as size_t,
                            seqnumin as *const libc::c_void,
                            (4 as libc::c_int as
                                 libc::c_ulong).wrapping_add(input_len),
                            hash.as_mut_ptr()) as libc::c_int;
            rpl_free(seqnumin as *mut libc::c_void);
            if res != 0 { return -(1 as libc::c_int) }
            *output_len =
                (4 as libc::c_int as
                     libc::c_ulong).wrapping_add(input_len).wrapping_add(10 as
                                                                             libc::c_int
                                                                             as
                                                                             libc::c_ulong).wrapping_add(2
                                                                                                             as
                                                                                                             libc::c_int
                                                                                                             as
                                                                                                             libc::c_ulong).wrapping_add(4
                                                                                                                                             as
                                                                                                                                             libc::c_int
                                                                                                                                             as
                                                                                                                                             libc::c_ulong);
            *output = malloc(*output_len) as *mut libc::c_char;
            if (*output).is_null() { return -(1 as libc::c_int) }
            len = 4 as libc::c_int as size_t;
            memcpy((*output).offset(len as isize) as *mut libc::c_void,
                   input as *const libc::c_void, input_len);
            len =
                (len as libc::c_ulong).wrapping_add(input_len) as size_t as
                    size_t;
            memcpy((*output).offset(len as isize) as *mut libc::c_void,
                   hash.as_mut_ptr() as *const libc::c_void,
                   10 as libc::c_int as libc::c_ulong);
            len =
                (len as
                     libc::c_ulong).wrapping_add(10 as libc::c_int as
                                                     libc::c_ulong) as size_t
                    as size_t;
            memcpy((*output).offset(len as isize) as *mut libc::c_void,
                   b"\x00\x01\x00" as *const u8 as *const libc::c_char as
                       *const libc::c_void,
                   2 as libc::c_int as libc::c_ulong);
            len =
                (len as
                     libc::c_ulong).wrapping_add(2 as libc::c_int as
                                                     libc::c_ulong) as size_t
                    as size_t;
            *(*output).offset(len as isize).offset(0 as libc::c_int as isize)
                =
                (sendseqnum >> 24 as libc::c_int &
                     0xff as libc::c_int as libc::c_ulong) as libc::c_char;
            *(*output).offset(len as isize).offset(1 as libc::c_int as isize)
                =
                (sendseqnum >> 16 as libc::c_int &
                     0xff as libc::c_int as libc::c_ulong) as libc::c_char;
            *(*output).offset(len as isize).offset(2 as libc::c_int as isize)
                =
                (sendseqnum >> 8 as libc::c_int &
                     0xff as libc::c_int as libc::c_ulong) as libc::c_char;
            *(*output).offset(len as isize).offset(3 as libc::c_int as isize)
                =
                (sendseqnum & 0xff as libc::c_int as libc::c_ulong) as
                    libc::c_char;
            len =
                (len as
                     libc::c_ulong).wrapping_add(4 as libc::c_int as
                                                     libc::c_ulong) as size_t
                    as size_t;
            *(*output).offset(0 as libc::c_int as isize) =
                (len.wrapping_sub(4 as libc::c_int as libc::c_ulong) >>
                     24 as libc::c_int & 0xff as libc::c_int as libc::c_ulong)
                    as libc::c_char;
            *(*output).offset(1 as libc::c_int as isize) =
                (len.wrapping_sub(4 as libc::c_int as libc::c_ulong) >>
                     16 as libc::c_int & 0xff as libc::c_int as libc::c_ulong)
                    as libc::c_char;
            *(*output).offset(2 as libc::c_int as isize) =
                (len.wrapping_sub(4 as libc::c_int as libc::c_ulong) >>
                     8 as libc::c_int & 0xff as libc::c_int as libc::c_ulong)
                    as libc::c_char;
            *(*output).offset(3 as libc::c_int as isize) =
                (len.wrapping_sub(4 as libc::c_int as libc::c_ulong) &
                     0xff as libc::c_int as libc::c_ulong) as libc::c_char
        } else {
            *output_len = input_len;
            *output = malloc(input_len) as *mut libc::c_char;
            if (*output).is_null() { return -(1 as libc::c_int) }
            memcpy(*output as *mut libc::c_void, input as *const libc::c_void,
                   input_len);
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn digest_md5_decode(mut input: *const libc::c_char,
                                           mut input_len: size_t,
                                           mut output: *mut *mut libc::c_char,
                                           mut output_len: *mut size_t,
                                           mut qop: digest_md5_qop,
                                           mut readseqnum: libc::c_ulong,
                                           mut key: *mut libc::c_char)
 -> libc::c_int {
    if qop as libc::c_uint &
           DIGEST_MD5_QOP_AUTH_CONF as libc::c_int as libc::c_uint != 0 {
        return -(1 as libc::c_int)
    } else {
        if qop as libc::c_uint &
               DIGEST_MD5_QOP_AUTH_INT as libc::c_int as libc::c_uint != 0 {
            let mut seqnumin: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut hash: [libc::c_char; 16] = [0; 16];
            let mut len: libc::c_ulong = 0;
            let mut tmpbuf: [libc::c_char; 4] = [0; 4];
            let mut res: libc::c_int = 0;
            if input_len < 4 as libc::c_int as libc::c_ulong {
                return -(2 as libc::c_int)
            }
            len =
                (*input.offset(3 as libc::c_int as isize) as libc::c_int &
                     0xff as libc::c_int |
                     (*input.offset(2 as libc::c_int as isize) as libc::c_int
                          & 0xff as libc::c_int) << 8 as libc::c_int |
                     (*input.offset(1 as libc::c_int as isize) as libc::c_int
                          & 0xff as libc::c_int) << 16 as libc::c_int |
                     (*input.offset(0 as libc::c_int as isize) as libc::c_int
                          & 0xff as libc::c_int) << 24 as libc::c_int) as
                    libc::c_ulong;
            if input_len <
                   (4 as libc::c_int as libc::c_ulong).wrapping_add(len) {
                return -(2 as libc::c_int)
            }
            len =
                len.wrapping_sub((10 as libc::c_int + 2 as libc::c_int +
                                      4 as libc::c_int) as libc::c_ulong);
            seqnumin =
                malloc((4 as libc::c_int as libc::c_ulong).wrapping_add(len))
                    as *mut libc::c_char;
            if seqnumin.is_null() { return -(1 as libc::c_int) }
            tmpbuf[0 as libc::c_int as usize] =
                (readseqnum >> 24 as libc::c_int &
                     0xff as libc::c_int as libc::c_ulong) as libc::c_char;
            tmpbuf[1 as libc::c_int as usize] =
                (readseqnum >> 16 as libc::c_int &
                     0xff as libc::c_int as libc::c_ulong) as libc::c_char;
            tmpbuf[2 as libc::c_int as usize] =
                (readseqnum >> 8 as libc::c_int &
                     0xff as libc::c_int as libc::c_ulong) as libc::c_char;
            tmpbuf[3 as libc::c_int as usize] =
                (readseqnum & 0xff as libc::c_int as libc::c_ulong) as
                    libc::c_char;
            memcpy(seqnumin as *mut libc::c_void,
                   tmpbuf.as_mut_ptr() as *const libc::c_void,
                   4 as libc::c_int as libc::c_ulong);
            memcpy(seqnumin.offset(4 as libc::c_int as isize) as
                       *mut libc::c_void,
                   input.offset(4 as libc::c_int as isize) as
                       *const libc::c_void, len);
            res =
                gc_hmac_md5(key as *const libc::c_void,
                            16 as libc::c_int as size_t,
                            seqnumin as *const libc::c_void,
                            (4 as libc::c_int as
                                 libc::c_ulong).wrapping_add(len),
                            hash.as_mut_ptr()) as libc::c_int;
            rpl_free(seqnumin as *mut libc::c_void);
            if res != 0 { return -(1 as libc::c_int) }
            if memcmp(hash.as_mut_ptr() as *const libc::c_void,
                      input.offset(input_len as
                                       isize).offset(-(4 as libc::c_int as
                                                           isize)).offset(-(2
                                                                                as
                                                                                libc::c_int
                                                                                as
                                                                                isize)).offset(-(10
                                                                                                     as
                                                                                                     libc::c_int
                                                                                                     as
                                                                                                     isize))
                          as *const libc::c_void,
                      10 as libc::c_int as libc::c_ulong) == 0 as libc::c_int
                   &&
                   memcmp(b"\x00\x01\x00" as *const u8 as *const libc::c_char
                              as *const libc::c_void,
                          input.offset(input_len as
                                           isize).offset(-(4 as libc::c_int as
                                                               isize)).offset(-(2
                                                                                    as
                                                                                    libc::c_int
                                                                                    as
                                                                                    isize))
                              as *const libc::c_void,
                          2 as libc::c_int as libc::c_ulong) ==
                       0 as libc::c_int &&
                   memcmp(tmpbuf.as_mut_ptr() as *const libc::c_void,
                          input.offset(input_len as
                                           isize).offset(-(4 as libc::c_int as
                                                               isize)) as
                              *const libc::c_void,
                          4 as libc::c_int as libc::c_ulong) ==
                       0 as libc::c_int {
                *output_len = len;
                *output = malloc(*output_len) as *mut libc::c_char;
                if (*output).is_null() { return -(1 as libc::c_int) }
                memcpy(*output as *mut libc::c_void,
                       input.offset(4 as libc::c_int as isize) as
                           *const libc::c_void, len);
            } else { return -(1 as libc::c_int) }
        } else {
            *output_len = input_len;
            *output = malloc(input_len) as *mut libc::c_char;
            if (*output).is_null() { return -(1 as libc::c_int) }
            memcpy(*output as *mut libc::c_void, input as *const libc::c_void,
                   input_len);
        }
    }
    return 0 as libc::c_int;
}
