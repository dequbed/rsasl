use ::libc;
use libc::size_t;
use crate::gsasl::scram::client::{scram_client_final, scram_client_first};
use crate::gsasl::scram::server::{scram_server_final, scram_server_first};

extern "C" {
    fn rpl_free(ptr: *mut libc::c_void);
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: size_t) -> *mut libc::c_void;
}
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

/* tokens.c --- Free allocated data in SCRAM tokens.
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
/* Get free. */
/* Get memset. */
#[no_mangle]
pub unsafe extern "C" fn scram_free_client_first(mut cf: *mut scram_client_first) {
    rpl_free((*cf).cbname as *mut libc::c_void);
    rpl_free((*cf).authzid as *mut libc::c_void);
    rpl_free((*cf).username as *mut libc::c_void);
    rpl_free((*cf).client_nonce as *mut libc::c_void);
    memset(cf as *mut libc::c_void, 0 as libc::c_int, ::std::mem::size_of::<scram_client_first>());
}
#[no_mangle]
pub unsafe extern "C" fn scram_free_server_first(mut sf: *mut scram_server_first) {
    rpl_free((*sf).nonce as *mut libc::c_void);
    rpl_free((*sf).salt as *mut libc::c_void);
    memset(sf as *mut libc::c_void, 0 as libc::c_int, ::std::mem::size_of::<scram_server_first>());
}
#[no_mangle]
pub unsafe extern "C" fn scram_free_client_final(mut cl: *mut scram_client_final) {
    rpl_free((*cl).cbind as *mut libc::c_void);
    rpl_free((*cl).nonce as *mut libc::c_void);
    rpl_free((*cl).proof as *mut libc::c_void);
    memset(cl as *mut libc::c_void, 0 as libc::c_int, ::std::mem::size_of::<scram_client_final>());
}
#[no_mangle]
pub unsafe extern "C" fn scram_free_server_final(mut sl: *mut scram_server_final) {
    rpl_free((*sl).verifier as *mut libc::c_void);
    memset(sl as *mut libc::c_void, 0 as libc::c_int, ::std::mem::size_of::<scram_server_final>());
}
