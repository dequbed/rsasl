use ::libc;
use libc::size_t;
use crate::gsasl::gsasl::{Gsasl_mechanism};
use crate::SASL;

extern "C" {
    fn strcat(_: *mut libc::c_char, _: *const libc::c_char)
     -> *mut libc::c_char;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
}
pub type C2RustUnnamed = libc::c_uint;
pub const GSASL_MAX_MECHANISM_SIZE: C2RustUnnamed = 20;
pub const GSASL_MIN_MECHANISM_SIZE: C2RustUnnamed = 1;

/* listmech.c --- List active client and server mechanisms.
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
 * License License along with GNU SASL Library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */
unsafe fn _gsasl_listmech(_ctx: &SASL,
                          _mechs: *mut Gsasl_mechanism,
                          _n_mechs: size_t,
                          _out: *mut *mut libc::c_char,
                          _clientp: libc::c_int,
) -> libc::c_int
{
    todo!();
    /*
    let mut sctx: *mut Gsasl_session = 0 as *mut Gsasl_session;
    let mut list: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: size_t = 0;
    let mut rc: libc::c_int = 0;
    list =
        calloc(n_mechs.wrapping_add(1) as u64,
               (GSASL_MAX_MECHANISM_SIZE as libc::c_int + 1 as libc::c_int) as
                   libc::c_ulong) as *mut libc::c_char;
    if list.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    i = 0;
    while i < n_mechs {
        if clientp != 0 {
            rc =
                gsasl_client_start(ctx, (*mechs.offset(i as isize)).name,
                                   &mut sctx)
        } else {
            rc =
                gsasl_server_start(ctx, (*mechs.offset(i as isize)).name,
                                   &mut sctx)
        }
        if rc == GSASL_OK as libc::c_int {
            gsasl_finish(&mut *sctx);
            strcat(list, (*mechs.offset(i as isize)).name.as_ptr() as *const libc::c_char);
            if i < n_mechs.wrapping_sub(1) {
                strcat(list, b" \x00" as *const u8 as *const libc::c_char);
            }
        }
        i = i.wrapping_add(1)
    }
    *out = list;
     */
}
/* *
 * gsasl_client_mechlist:
 * @ctx: libgsasl handle.
 * @out: newly allocated output character array.
 *
 * Return a newly allocated string containing SASL names, separated by
 * space, of mechanisms supported by the libgsasl client.  @out is
 * allocated by this function, and it is the responsibility of caller
 * to deallocate it.
 *
 * Return value: Returns %GSASL_OK if successful, or error code.
 **/
#[no_mangle]
pub unsafe fn gsasl_client_mechlist(_ctx: &SASL, _out: &mut *mut libc::c_char)
 -> libc::c_int {
    todo!()
}
pub unsafe fn gsasl_server_mechlist(_ctx: &SASL, _out: *mut *mut libc::c_char)
 -> libc::c_int {
    todo!()
}
