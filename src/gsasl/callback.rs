use ::libc;
use crate::gsasl::consts::{GSASL_NO_CALLBACK, Gsasl_property};
use crate::gsasl::gsasl::{Gsasl, Gsasl_callback_function, Gsasl_session};

/* callback.c --- Callback handling.
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
/* *
 * gsasl_callback_set:
 * @ctx: handle received from gsasl_init().
 * @cb: pointer to function implemented by application.
 *
 * Store the pointer to the application provided callback in the
 * library handle.  The callback will be used, via gsasl_callback(),
 * by mechanisms to discover various parameters (such as username and
 * passwords).  The callback function will be called with a
 * Gsasl_property value indicating the requested behaviour.  For
 * example, for %GSASL_ANONYMOUS_TOKEN, the function is expected to
 * invoke gsasl_property_set(@CTX, %GSASL_ANONYMOUS_TOKEN, "token")
 * where "token" is the anonymous token the application wishes the
 * SASL mechanism to use.  See the manual for the meaning of all
 * parameters.
 *
 * Since: 0.2.0
 **/
#[no_mangle]
pub unsafe fn gsasl_callback_set(mut ctx: *mut Gsasl,
                                            mut cb: Gsasl_callback_function) {
    (*ctx).cb = cb;
}
/* *
 * gsasl_callback:
 * @ctx: handle received from gsasl_init(), may be NULL to derive it
 *   from @sctx.
 * @sctx: session handle.
 * @prop: enumerated value of Gsasl_property type.
 *
 * Invoke the application callback.  The @prop value indicate what the
 * callback is expected to do.  For example, for
 * %GSASL_ANONYMOUS_TOKEN, the function is expected to invoke
 * gsasl_property_set(@SCTX, %GSASL_ANONYMOUS_TOKEN, "token") where
 * "token" is the anonymous token the application wishes the SASL
 * mechanism to use.  See the manual for the meaning of all
 * parameters.
 *
 * Return value: Returns whatever the application callback returns, or
 *   %GSASL_NO_CALLBACK if no application was known.
 *
 * Since: 0.2.0
 **/
#[no_mangle]
pub unsafe fn gsasl_callback(mut ctx: *mut Gsasl,
                             sctx: *mut Gsasl_session,
                             prop: Gsasl_property)
 -> libc::c_int {
    if ctx.is_null() && sctx.is_null() {
        return GSASL_NO_CALLBACK as libc::c_int
    }
    if ctx.is_null() { ctx = (*sctx).ctx }
    if (*ctx).cb.is_some() {
        return (*ctx).cb.expect("non-null function pointer")(ctx, sctx, prop)
    }
    return GSASL_NO_CALLBACK as libc::c_int;
}
