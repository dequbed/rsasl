use crate::gsasl::gl::free::rpl_free;
use crate::mechanisms::digest_md5::parser::{
    digest_md5_challenge, digest_md5_finish, digest_md5_response,
};
use ::libc;
use libc::{memset, size_t};

/* free.h --- Free allocated data in DIGEST-MD5 token structures.
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
/* free.h --- Free allocated data in DIGEST-MD5 token structures.
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
/* Get prototypes. */
/* Get free. */
/* Get memset. */
#[no_mangle]
pub unsafe fn digest_md5_free_challenge(c: *mut digest_md5_challenge) {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < (*c).nrealms {
        rpl_free(*(*c).realms.offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1)
    }
    rpl_free((*c).realms as *mut libc::c_void);
    rpl_free((*c).nonce as *mut libc::c_void);
    memset(
        c as *mut libc::c_void,
        0,
        ::std::mem::size_of::<digest_md5_challenge>(),
    );
}
#[no_mangle]
pub unsafe fn digest_md5_free_response(r: *mut digest_md5_response) {
    rpl_free((*r).username as *mut libc::c_void);
    rpl_free((*r).realm as *mut libc::c_void);
    rpl_free((*r).nonce as *mut libc::c_void);
    rpl_free((*r).cnonce as *mut libc::c_void);
    rpl_free((*r).digesturi as *mut libc::c_void);
    rpl_free((*r).authzid as *mut libc::c_void);
    memset(
        r as *mut libc::c_void,
        0,
        ::std::mem::size_of::<digest_md5_response>(),
    );
}
#[no_mangle]
pub unsafe fn digest_md5_free_finish(f: *mut digest_md5_finish) {
    memset(
        f as *mut libc::c_void,
        0,
        ::std::mem::size_of::<digest_md5_finish>(),
    );
}
