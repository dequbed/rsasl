use ::libc;
use libc::size_t;
use crate::gsasl::consts::{Gsasl_property, GSASL_SCRAM_SALTED_PASSWORD};
use crate::gsasl::gsasl::Gsasl_session;
use crate::gsasl::mechtools::Gsasl_hash;

extern "C" {
    fn gsasl_hash_length(hash: Gsasl_hash) -> size_t;
    fn gsasl_property_set(sctx: *mut Gsasl_session, prop: Gsasl_property,
                          data: *const libc::c_char) -> libc::c_int;
    fn _gsasl_hex_encode(in_0: *const libc::c_char, inlen: size_t,
                         out: *mut libc::c_char);
}
/* tools.h --- Shared client/server SCRAM code
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
/* tools.c --- Shared client/server SCRAM code
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
/* Hex encode HASHBUF which is HASH digest output and set salted
   password property to the hex encoded value. */
#[no_mangle]
pub unsafe extern "C" fn set_saltedpassword(mut sctx: *mut Gsasl_session,
                                            mut hash: Gsasl_hash,
                                            mut hashbuf: *const libc::c_char)
 -> libc::c_int {
    let mut hexstr: [libc::c_char; 65] = [0; 65];
    _gsasl_hex_encode(hashbuf, gsasl_hash_length(hash), hexstr.as_mut_ptr());
    return gsasl_property_set(sctx, GSASL_SCRAM_SALTED_PASSWORD,
                              hexstr.as_mut_ptr());
}
