use ::libc;
extern "C" {
    /* parser.h --- DIGEST-MD5 parser.
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
    fn digest_md5_getsubopt(optionp: *mut *mut libc::c_char,
                            tokens: *const *const libc::c_char,
                            valuep: *mut *mut libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
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
    #[no_mangle]
    fn rpl_free(_: *mut libc::c_void);
}
pub const DIGEST_MD5_QOP_AUTH_CONF: digest_md5_qop = 4;
pub const QOP_AUTH_CONF: C2RustUnnamed = 2;
pub const DIGEST_MD5_QOP_AUTH_INT: digest_md5_qop = 2;
pub const QOP_AUTH_INT: C2RustUnnamed = 1;
pub const DIGEST_MD5_QOP_AUTH: digest_md5_qop = 1;
/* the order must match the following struct */
pub const QOP_AUTH: C2RustUnnamed = 0;
pub type C2RustUnnamed = libc::c_uint;
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
/* qop.h --- Prototypes for DIGEST-MD5 qop handling.
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
/* qop.c --- DIGEST-MD5 QOP handling.
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
/* Get prototypes. */
#[no_mangle]
pub unsafe extern "C" fn digest_md5_qopstr2qops(mut qopstr:
                                                    *const libc::c_char)
 -> libc::c_int {
    let mut qops: libc::c_int = 0 as libc::c_int;
    let qop_opts: [*const libc::c_char; 4] =
        [b"qop-auth\x00" as *const u8 as *const libc::c_char,
         b"qop-int\x00" as *const u8 as *const libc::c_char,
         b"qop-conf\x00" as *const u8 as *const libc::c_char,
         0 as *const libc::c_char];
    let mut subsubopts: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut val: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut qopdup: *mut libc::c_char = 0 as *mut libc::c_char;
    if qopstr.is_null() { return 0 as libc::c_int }
    qopdup = strdup(qopstr);
    if qopdup.is_null() { return -(1 as libc::c_int) }
    subsubopts = qopdup;
    while *subsubopts as libc::c_int != '\u{0}' as i32 {
        match digest_md5_getsubopt(&mut subsubopts, qop_opts.as_ptr(),
                                   &mut val) {
            0 => { qops |= DIGEST_MD5_QOP_AUTH as libc::c_int }
            1 => { qops |= DIGEST_MD5_QOP_AUTH_INT as libc::c_int }
            2 => { qops |= DIGEST_MD5_QOP_AUTH_CONF as libc::c_int }
            _ => { }
        }
    }
    rpl_free(qopdup as *mut libc::c_void);
    return qops;
}
#[no_mangle]
pub unsafe extern "C" fn digest_md5_qops2qopstr(mut qops: libc::c_int)
 -> *const libc::c_char {
    let mut qopstr: [*const libc::c_char; 8] =
        [b"qop-auth\x00" as *const u8 as *const libc::c_char,
         b"qop-auth\x00" as *const u8 as *const libc::c_char,
         b"qop-int\x00" as *const u8 as *const libc::c_char,
         b"qop-auth, qop-int\x00" as *const u8 as *const libc::c_char,
         b"qop-conf\x00" as *const u8 as *const libc::c_char,
         b"qop-auth, qop-conf\x00" as *const u8 as *const libc::c_char,
         b"qop-int, qop-conf\x00" as *const u8 as *const libc::c_char,
         b"qop-auth, qop-int, qop-conf\x00" as *const u8 as
             *const libc::c_char];
    return qopstr[(qops & 0x7 as libc::c_int) as usize];
}
