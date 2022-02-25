use crate::gsasl::gl::free::rpl_free;
use crate::mechanisms::digest_md5::getsubopt::digest_md5_getsubopt;
use ::libc;
use libc::strdup;

pub type digest_md5_qop = libc::c_uint;
pub const DIGEST_MD5_QOP_AUTH_CONF: digest_md5_qop = 4;
pub const DIGEST_MD5_QOP_AUTH_INT: digest_md5_qop = 2;
pub const DIGEST_MD5_QOP_AUTH: digest_md5_qop = 1;

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
pub unsafe fn digest_md5_qopstr2qops(qopstr: *const libc::c_char) -> libc::c_int {
    let mut qops: libc::c_int = 0 as libc::c_int;
    let qop_opts: [*const libc::c_char; 4] = [
        b"qop-auth\x00" as *const u8 as *const libc::c_char,
        b"qop-int\x00" as *const u8 as *const libc::c_char,
        b"qop-conf\x00" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
    ];
    let mut subsubopts;
    let mut val: *mut libc::c_char = 0 as *mut libc::c_char;
    let qopdup;
    if qopstr.is_null() {
        return 0 as libc::c_int;
    }
    qopdup = strdup(qopstr);
    if qopdup.is_null() {
        return -(1 as libc::c_int);
    }
    subsubopts = qopdup;
    while *subsubopts as libc::c_int != '\u{0}' as i32 {
        match digest_md5_getsubopt(&mut subsubopts, qop_opts.as_ptr(), &mut val) {
            0 => qops |= DIGEST_MD5_QOP_AUTH as libc::c_int,
            1 => qops |= DIGEST_MD5_QOP_AUTH_INT as libc::c_int,
            2 => qops |= DIGEST_MD5_QOP_AUTH_CONF as libc::c_int,
            _ => {}
        }
    }
    rpl_free(qopdup as *mut libc::c_void);
    return qops;
}
#[no_mangle]
pub unsafe fn digest_md5_qops2qopstr(qops: libc::c_int) -> *const libc::c_char {
    let qopstr: [*const libc::c_char; 8] = [
        b"qop-auth\x00" as *const u8 as *const libc::c_char,
        b"qop-auth\x00" as *const u8 as *const libc::c_char,
        b"qop-int\x00" as *const u8 as *const libc::c_char,
        b"qop-auth, qop-int\x00" as *const u8 as *const libc::c_char,
        b"qop-conf\x00" as *const u8 as *const libc::c_char,
        b"qop-auth, qop-conf\x00" as *const u8 as *const libc::c_char,
        b"qop-int, qop-conf\x00" as *const u8 as *const libc::c_char,
        b"qop-auth, qop-int, qop-conf\x00" as *const u8 as *const libc::c_char,
    ];
    return qopstr[(qops & 0x7 as libc::c_int) as usize];
}
