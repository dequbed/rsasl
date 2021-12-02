use ::libc;
use libc::size_t;
use crate::gsasl::gsasl::{Gsasl_mechanism, Gsasl_mechanism_functions, Gsasl_session};

extern "C" {
    fn _gsasl_scram_sha256_plus_client_start(sctx: *mut Gsasl_session,
                                             mech_data:
                                                 *mut *mut libc::c_void)
     -> libc::c_int;
    fn _gsasl_scram_sha256_plus_server_start(sctx: *mut Gsasl_session,
                                             mech_data:
                                                 *mut *mut libc::c_void)
     -> libc::c_int;
    fn _gsasl_scram_sha256_client_start(sctx: *mut Gsasl_session,
                                        mech_data: *mut *mut libc::c_void)
     -> libc::c_int;
    fn _gsasl_scram_sha256_server_start(sctx: *mut Gsasl_session,
                                        mech_data: *mut *mut libc::c_void)
     -> libc::c_int;
    fn _gsasl_scram_sha1_plus_client_start(sctx: *mut Gsasl_session,
                                           mech_data: *mut *mut libc::c_void)
     -> libc::c_int;
    fn _gsasl_scram_sha1_plus_server_start(sctx: *mut Gsasl_session,
                                           mech_data: *mut *mut libc::c_void)
     -> libc::c_int;
    fn _gsasl_scram_sha1_client_start(sctx: *mut Gsasl_session,
                                      mech_data: *mut *mut libc::c_void)
     -> libc::c_int;
    fn _gsasl_scram_client_step(sctx: *mut Gsasl_session,
                                mech_data: *mut libc::c_void,
                                input: *const libc::c_char, input_len: size_t,
                                output: *mut *mut libc::c_char,
                                output_len: *mut size_t) -> libc::c_int;
    fn _gsasl_scram_client_finish(sctx: *mut Gsasl_session,
                                  mech_data: *mut libc::c_void);
    fn _gsasl_scram_sha1_server_start(sctx: *mut Gsasl_session,
                                      mech_data: *mut *mut libc::c_void)
     -> libc::c_int;
    fn _gsasl_scram_server_step(sctx: *mut Gsasl_session,
                                mech_data: *mut libc::c_void,
                                input: *const libc::c_char, input_len: size_t,
                                output: *mut *mut libc::c_char,
                                output_len: *mut size_t) -> libc::c_int;
    /* scram.h --- Prototypes for SCRAM mechanism
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
    fn _gsasl_scram_server_finish(sctx: *mut Gsasl_session,
                                  mech_data: *mut libc::c_void);
}
/* mechinfo.c --- Definition of SCRAM mechanism.
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
/* Get specification. */
#[no_mangle]
pub static mut gsasl_scram_sha1_mechanism: Gsasl_mechanism =
    {
        {
            let mut init =
                Gsasl_mechanism{name:
                                    b"SCRAM-SHA-1\x00" as *const u8 as
                                        *const libc::c_char,
                                client:
                                    {
                                        let mut init =
                                            Gsasl_mechanism_functions{init:
                                                                          None,
                                                                      done:
                                                                          None,
                                                                      start:
                                                                          Some(_gsasl_scram_sha1_client_start
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut *mut libc::c_void)
                                                                                       ->
                                                                                           libc::c_int),
                                                                      step:
                                                                          Some(_gsasl_scram_client_step
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
                                                                          Some(_gsasl_scram_client_finish
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut libc::c_void)
                                                                                       ->
                                                                                           ()),
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
                                                                          Some(_gsasl_scram_sha1_server_start
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut *mut libc::c_void)
                                                                                       ->
                                                                                           libc::c_int),
                                                                      step:
                                                                          Some(_gsasl_scram_server_step
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
                                                                          Some(_gsasl_scram_server_finish
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut libc::c_void)
                                                                                       ->
                                                                                           ()),
                                                                      encode:
                                                                          None,
                                                                      decode:
                                                                          None,};
                                        init
                                    },};
            init
        }
    };
#[no_mangle]
pub static mut gsasl_scram_sha1_plus_mechanism: Gsasl_mechanism =
    {
        {
            let mut init =
                Gsasl_mechanism{name:
                                    b"SCRAM-SHA-1-PLUS\x00" as *const u8 as
                                        *const libc::c_char,
                                client:
                                    {
                                        let mut init =
                                            Gsasl_mechanism_functions{init:
                                                                          None,
                                                                      done:
                                                                          None,
                                                                      start:
                                                                          Some(_gsasl_scram_sha1_plus_client_start
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut *mut libc::c_void)
                                                                                       ->
                                                                                           libc::c_int),
                                                                      step:
                                                                          Some(_gsasl_scram_client_step
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
                                                                          Some(_gsasl_scram_client_finish
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut libc::c_void)
                                                                                       ->
                                                                                           ()),
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
                                                                          Some(_gsasl_scram_sha1_plus_server_start
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut *mut libc::c_void)
                                                                                       ->
                                                                                           libc::c_int),
                                                                      step:
                                                                          Some(_gsasl_scram_server_step
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
                                                                          Some(_gsasl_scram_server_finish
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut libc::c_void)
                                                                                       ->
                                                                                           ()),
                                                                      encode:
                                                                          None,
                                                                      decode:
                                                                          None,};
                                        init
                                    },};
            init
        }
    };
#[no_mangle]
pub static mut gsasl_scram_sha256_mechanism: Gsasl_mechanism =
    {
        {
            let mut init =
                Gsasl_mechanism{name:
                                    b"SCRAM-SHA-256\x00" as *const u8 as
                                        *const libc::c_char,
                                client:
                                    {
                                        let mut init =
                                            Gsasl_mechanism_functions{init:
                                                                          None,
                                                                      done:
                                                                          None,
                                                                      start:
                                                                          Some(_gsasl_scram_sha256_client_start
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut *mut libc::c_void)
                                                                                       ->
                                                                                           libc::c_int),
                                                                      step:
                                                                          Some(_gsasl_scram_client_step
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
                                                                          Some(_gsasl_scram_client_finish
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut libc::c_void)
                                                                                       ->
                                                                                           ()),
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
                                                                          Some(_gsasl_scram_sha256_server_start
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut *mut libc::c_void)
                                                                                       ->
                                                                                           libc::c_int),
                                                                      step:
                                                                          Some(_gsasl_scram_server_step
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
                                                                          Some(_gsasl_scram_server_finish
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut libc::c_void)
                                                                                       ->
                                                                                           ()),
                                                                      encode:
                                                                          None,
                                                                      decode:
                                                                          None,};
                                        init
                                    },};
            init
        }
    };
#[no_mangle]
pub static mut gsasl_scram_sha256_plus_mechanism: Gsasl_mechanism =
    {
        {
            let mut init =
                Gsasl_mechanism{name:
                                    b"SCRAM-SHA-256-PLUS\x00" as *const u8 as
                                        *const libc::c_char,
                                client:
                                    {
                                        let mut init =
                                            Gsasl_mechanism_functions{init:
                                                                          None,
                                                                      done:
                                                                          None,
                                                                      start:
                                                                          Some(_gsasl_scram_sha256_plus_client_start
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut *mut libc::c_void)
                                                                                       ->
                                                                                           libc::c_int),
                                                                      step:
                                                                          Some(_gsasl_scram_client_step
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
                                                                          Some(_gsasl_scram_client_finish
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut libc::c_void)
                                                                                       ->
                                                                                           ()),
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
                                                                          Some(_gsasl_scram_sha256_plus_server_start
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut *mut libc::c_void)
                                                                                       ->
                                                                                           libc::c_int),
                                                                      step:
                                                                          Some(_gsasl_scram_server_step
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
                                                                          Some(_gsasl_scram_server_finish
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut libc::c_void)
                                                                                       ->
                                                                                           ()),
                                                                      encode:
                                                                          None,
                                                                      decode:
                                                                          None,};
                                        init
                                    },};
            init
        }
    };
