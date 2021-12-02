use ::libc;
extern "C" {
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
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
}
pub type size_t = libc::c_ulong;
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
/* Get size_t. */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_client_first {
    pub cbflag: libc::c_char,
    pub cbname: *mut libc::c_char,
    pub authzid: *mut libc::c_char,
    pub username: *mut libc::c_char,
    pub client_nonce: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_server_first {
    pub nonce: *mut libc::c_char,
    pub salt: *mut libc::c_char,
    pub iter: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_client_final {
    pub cbind: *mut libc::c_char,
    pub nonce: *mut libc::c_char,
    pub proof: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct scram_server_final {
    pub verifier: *mut libc::c_char,
}
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
pub unsafe extern "C" fn scram_free_client_first(mut cf:
                                                     *mut scram_client_first) {
    rpl_free((*cf).cbname as *mut libc::c_void);
    rpl_free((*cf).authzid as *mut libc::c_void);
    rpl_free((*cf).username as *mut libc::c_void);
    rpl_free((*cf).client_nonce as *mut libc::c_void);
    memset(cf as *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<scram_client_first>() as libc::c_ulong);
}
#[no_mangle]
pub unsafe extern "C" fn scram_free_server_first(mut sf:
                                                     *mut scram_server_first) {
    rpl_free((*sf).nonce as *mut libc::c_void);
    rpl_free((*sf).salt as *mut libc::c_void);
    memset(sf as *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<scram_server_first>() as libc::c_ulong);
}
#[no_mangle]
pub unsafe extern "C" fn scram_free_client_final(mut cl:
                                                     *mut scram_client_final) {
    rpl_free((*cl).cbind as *mut libc::c_void);
    rpl_free((*cl).nonce as *mut libc::c_void);
    rpl_free((*cl).proof as *mut libc::c_void);
    memset(cl as *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<scram_client_final>() as libc::c_ulong);
}
#[no_mangle]
pub unsafe extern "C" fn scram_free_server_final(mut sl:
                                                     *mut scram_server_final) {
    rpl_free((*sl).verifier as *mut libc::c_void);
    memset(sl as *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<scram_server_final>() as libc::c_ulong);
}
