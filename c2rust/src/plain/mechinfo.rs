use ::libc;
use libc::size_t;
use crate::gsasl::{Gsasl, Gsasl_mechanism, Gsasl_mechanism_functions, Gsasl_session};
use crate::plain::client::_gsasl_plain_client_step;
use crate::plain::server::_gsasl_plain_server_step;

/* mechinfo.c --- Definition of PLAIN mechanism.
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
/* Get specification. */
#[no_mangle]
pub static mut gsasl_plain_mechanism: Gsasl_mechanism =
    unsafe {
        {
            let mut init =
                Gsasl_mechanism{name:
                                    b"PLAIN\x00" as *const u8 as
                                        *const libc::c_char,
                                client:
                                    {
                                        let mut init =
                                            Gsasl_mechanism_functions{init:
                                                                          None,
                                                                      done:
                                                                          None,
                                                                      start:
                                                                          None,
                                                                      step:
                                                                          Some(_gsasl_plain_client_step
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut libc::c_void,
                                                                                                        _:
                                                                                                            *const libc::c_char,
                                                                                                        _:
                                                                                                            size_t,
                                                                                                        _:
                                                                                                            *mut *mut libc::c_char,
                                                                                                        _:
                                                                                                            *mut size_t)
                                                                                       ->
                                                                                           libc::c_int),
                                                                      finish:
                                                                          None,
                                                                      encode:
                                                                          None,
                                                                      decode:
                                                                          None,};
                                        init
                                    },
                                server:
                                    {
                                        let mut init =
                                            Gsasl_mechanism_functions{init:
                                                                          None,
                                                                      done:
                                                                          None,
                                                                      start:
                                                                          None,
                                                                      step:
                                                                          Some(_gsasl_plain_server_step
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut libc::c_void,
                                                                                                        _:
                                                                                                            *const libc::c_char,
                                                                                                        _:
                                                                                                            size_t,
                                                                                                        _:
                                                                                                            *mut *mut libc::c_char,
                                                                                                        _:
                                                                                                            *mut size_t)
                                                                                       ->
                                                                                           libc::c_int),
                                                                      finish:
                                                                          None,
                                                                      encode:
                                                                          None,
                                                                      decode:
                                                                          None,};
                                        init
                                    },};
            init
        }
    };
