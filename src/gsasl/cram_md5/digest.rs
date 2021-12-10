use ::libc;
use libc::size_t;
use crate::gsasl::gc::Gc_rc;
use crate::gsasl::gl::gc_gnulib::gc_hmac_md5;

extern "C" {
    fn strlen(_: *const libc::c_char) -> size_t;
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
/* digest.h --- Generate a CRAM-MD5 hex encoded HMAC-MD5 response string.
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
/* Get size_t. */
/* Compute hex encoded HMAC-MD5 on the CHALLENGELEN long string
   CHALLENGE, keyed with SECRET of length SECRETLEN.  Use a
   CHALLENGELEN or SECRETLEN of 0 to indicate that CHALLENGE or
   SECRET, respectively, is zero terminated.  The RESPONSE buffer must
   be allocated by the caller, and must have room for
   CRAM_MD5_DIGEST_LEN characters.*/
#[no_mangle]
pub unsafe fn cram_md5_digest(mut challenge: *const libc::c_char,
                                         mut challengelen: size_t,
                                         mut secret: *const libc::c_char,
                                         mut secretlen: size_t,
                                         mut response: *mut libc::c_char) {
    let mut hash: [libc::c_char; 16] = [0; 16];
    let mut i: size_t = 0;
    gc_hmac_md5(secret as *const libc::c_void,
                if secretlen != 0 { secretlen } else { strlen(secret) },
                challenge as *const libc::c_void,
                if challengelen != 0 {
                    challengelen
                } else { strlen(challenge) }, hash.as_mut_ptr());
    i = 0 as libc::c_int as size_t;
    while i < 16 {
        let fresh0 = response;
        response = response.offset(1);
        *fresh0 =
            if hash[i as usize] as libc::c_int >> 4 as libc::c_int &
                   0xf as libc::c_int > 9 as libc::c_int {
                ('a' as i32 +
                     (hash[i as usize] as libc::c_int >> 4 as libc::c_int &
                          0xf as libc::c_int)) - 10 as libc::c_int
            } else {
                ('0' as i32) +
                    (hash[i as usize] as libc::c_int >> 4 as libc::c_int &
                         0xf as libc::c_int)
            } as libc::c_char;
        let fresh1 = response;
        response = response.offset(1);
        *fresh1 =
            if hash[i as usize] as libc::c_int & 0xf as libc::c_int >
                   9 as libc::c_int {
                ('a' as i32 +
                     (hash[i as usize] as libc::c_int & 0xf as libc::c_int)) -
                    10 as libc::c_int
            } else {
                ('0' as i32) +
                    (hash[i as usize] as libc::c_int & 0xf as libc::c_int)
            } as libc::c_char;
        i = i.wrapping_add(1)
    };
}
