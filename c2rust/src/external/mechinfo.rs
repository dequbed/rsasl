use ::libc;
extern "C" {
    pub type Gsasl;
    pub type Gsasl_session;
    #[no_mangle]
    fn _gsasl_external_client_step(sctx: *mut Gsasl_session,
                                   mech_data: *mut libc::c_void,
                                   input: *const libc::c_char,
                                   input_len: size_t,
                                   output: *mut *mut libc::c_char,
                                   output_len: *mut size_t) -> libc::c_int;
    #[no_mangle]
    fn _gsasl_external_server_step(sctx: *mut Gsasl_session,
                                   mech_data: *mut libc::c_void,
                                   input: *const libc::c_char,
                                   input_len: size_t,
                                   output: *mut *mut libc::c_char,
                                   output_len: *mut size_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type Gsasl_init_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl) -> libc::c_int>;
pub type Gsasl_done_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl) -> ()>;
pub type Gsasl_start_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl_session,
                                _: *mut *mut libc::c_void) -> libc::c_int>;
pub type Gsasl_step_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl_session, _: *mut libc::c_void,
                                _: *const libc::c_char, _: size_t,
                                _: *mut *mut libc::c_char, _: *mut size_t)
               -> libc::c_int>;
pub type Gsasl_finish_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl_session, _: *mut libc::c_void)
               -> ()>;
pub type Gsasl_code_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl_session, _: *mut libc::c_void,
                                _: *const libc::c_char, _: size_t,
                                _: *mut *mut libc::c_char, _: *mut size_t)
               -> libc::c_int>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Gsasl_mechanism_functions {
    pub init: Gsasl_init_function,
    pub done: Gsasl_done_function,
    pub start: Gsasl_start_function,
    pub step: Gsasl_step_function,
    pub finish: Gsasl_finish_function,
    pub encode: Gsasl_code_function,
    pub decode: Gsasl_code_function,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Gsasl_mechanism {
    pub name: *const libc::c_char,
    pub client: Gsasl_mechanism_functions,
    pub server: Gsasl_mechanism_functions,
}
/* mechinfo.c --- Definition of EXTERNAL mechanism.
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
pub static mut gsasl_external_mechanism: Gsasl_mechanism =
    unsafe {
        {
            let mut init =
                Gsasl_mechanism{name:
                                    b"EXTERNAL\x00" as *const u8 as
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
                                                                          Some(_gsasl_external_client_step
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
                                                                          Some(_gsasl_external_server_step
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
