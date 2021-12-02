use ::libc;
extern "C" {
    /* *
   * Gsasl:
   *
   * Handle to global library context.
   */
    pub type Gsasl;
    /* *
   * Gsasl_session:
   *
   * Handle to SASL session context.
   */
    pub type Gsasl_session;
    #[no_mangle]
    fn _gsasl_login_client_start(sctx: *mut Gsasl_session,
                                 mech_data: *mut *mut libc::c_void)
     -> libc::c_int;
    #[no_mangle]
    fn _gsasl_login_server_finish(sctx: *mut Gsasl_session,
                                  mech_data: *mut libc::c_void);
    #[no_mangle]
    fn _gsasl_login_server_step(sctx: *mut Gsasl_session,
                                mech_data: *mut libc::c_void,
                                input: *const libc::c_char, input_len: size_t,
                                output: *mut *mut libc::c_char,
                                output_len: *mut size_t) -> libc::c_int;
    #[no_mangle]
    fn _gsasl_login_server_start(sctx: *mut Gsasl_session,
                                 mech_data: *mut *mut libc::c_void)
     -> libc::c_int;
    #[no_mangle]
    fn _gsasl_login_client_finish(sctx: *mut Gsasl_session,
                                  mech_data: *mut libc::c_void);
    #[no_mangle]
    fn _gsasl_login_client_step(sctx: *mut Gsasl_session,
                                mech_data: *mut libc::c_void,
                                input: *const libc::c_char, input_len: size_t,
                                output: *mut *mut libc::c_char,
                                output_len: *mut size_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
/* gsasl-mech.h --- Header file for mechanism handling in GNU SASL Library.
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
 * SECTION:gsasl-mech
 * @title: gsasl-mech.h
 * @short_description: register new application-defined mechanism
 *
 * The builtin mechanisms should suffice for most applications.
 * Applications can register a new mechanism in the library using
 * application-supplied functions.  The mechanism will operate as the
 * builtin mechanisms, and the supplied functions will be invoked when
 * necessary.  The application uses the normal logic, e.g., calls
 * gsasl_client_start() followed by a sequence of calls to
 * gsasl_step() and finally gsasl_finish().
 */
/* *
 * Gsasl_init_function:
 * @ctx: a %Gsasl libgsasl handle.
 *
 * The implementation of this function pointer should fail if the
 * mechanism for some reason is not available for further use.
 *
 * Return value: Returns %GSASL_OK iff successful.
 **/
pub type Gsasl_init_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl) -> libc::c_int>;
/* *
 * Gsasl_done_function:
 * @ctx: a %Gsasl libgsasl handle.
 *
 * The implementation of this function pointer deallocate all
 * resources associated with the mechanism.
 **/
pub type Gsasl_done_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl) -> ()>;
/* *
 * Gsasl_start_function:
 * @sctx: a %Gsasl_session session handle.
 * @mech_data: pointer to void* with mechanism-specific data.
 *
 * The implementation of this function should start a new
 * authentication process.
 *
 * Return value: Returns %GSASL_OK iff successful.
 **/
pub type Gsasl_start_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl_session,
                                _: *mut *mut libc::c_void) -> libc::c_int>;
/* *
 * Gsasl_step_function:
 * @sctx: a %Gsasl_session session handle.
 * @mech_data: pointer to void* with mechanism-specific data.
 * @input: input byte array.
 * @input_len: size of input byte array.
 * @output: newly allocated output byte array.
 * @output_len: pointer to output variable with size of output byte array.
 *
 * The implementation of this function should perform one step of the
 * authentication process.
 *
 * This reads data from the other end (from @input and @input_len),
 * processes it (potentially invoking callbacks to the application),
 * and writes data to server (into newly allocated variable @output
 * and @output_len that indicate the length of @output).
 *
 * The contents of the @output buffer is unspecified if this functions
 * returns anything other than %GSASL_OK or %GSASL_NEEDS_MORE.  If
 * this function return %GSASL_OK or %GSASL_NEEDS_MORE, however, the
 * @output buffer is allocated by this function, and it is the
 * responsibility of caller to deallocate it by calling
 * gsasl_free(@output).
 *
 * Return value: Returns %GSASL_OK if authenticated terminated
 *   successfully, %GSASL_NEEDS_MORE if more data is needed, or error
 *   code.
 **/
pub type Gsasl_step_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl_session, _: *mut libc::c_void,
                                _: *const libc::c_char, _: size_t,
                                _: *mut *mut libc::c_char, _: *mut size_t)
               -> libc::c_int>;
/* *
 * Gsasl_finish_function:
 * @sctx: a %Gsasl_session session handle.
 * @mech_data: pointer to void* with mechanism-specific data.
 *
 * The implementation of this function should release all resources
 * associated with the particular authentication process.
 **/
pub type Gsasl_finish_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl_session, _: *mut libc::c_void)
               -> ()>;
/* *
 * Gsasl_code_function:
 * @sctx: a %Gsasl_session session handle.
 * @mech_data: pointer to void* with mechanism-specific data.
 * @input: input byte array.
 * @input_len: size of input byte array.
 * @output: newly allocated output byte array.
 * @output_len: pointer to output variable with size of output byte array.
 *
 * The implementation of this function should perform data encoding or
 * decoding for the mechanism, after authentication has completed.
 * This might mean that data is integrity or privacy protected.
 *
 * The @output buffer is allocated by this function, and it is the
 * responsibility of caller to deallocate it by calling
 * gsasl_free(@output).
 *
 * Return value: Returns %GSASL_OK if encoding was successful,
 *   otherwise an error code.
 **/
pub type Gsasl_code_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl_session, _: *mut libc::c_void,
                                _: *const libc::c_char, _: size_t,
                                _: *mut *mut libc::c_char, _: *mut size_t)
               -> libc::c_int>;
/* *
 * Gsasl_mechanism_functions:
 * @init: a Gsasl_init_function().
 * @done: a Gsasl_done_function().
 * @start: a Gsasl_start_function().
 * @step: a Gsasl_step_function().
 * @finish: a Gsasl_finish_function().
 * @encode: a Gsasl_code_function().
 * @decode: a Gsasl_code_function().
 *
 * Holds all function pointers to implement a mechanism, in either
 * client or server mode.
 */
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
/* *
 * Gsasl_mechanism:
 * @name: string holding name of mechanism, e.g., "PLAIN".
 * @client: client-side #Gsasl_mechanism_functions structure.
 * @server: server-side #Gsasl_mechanism_functions structure.
 *
 * Holds all implementation details about a mechanism.
 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Gsasl_mechanism {
    pub name: *const libc::c_char,
    pub client: Gsasl_mechanism_functions,
    pub server: Gsasl_mechanism_functions,
}
/* mechinfo.c --- Definition of LOGIN mechanism.
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
pub static mut gsasl_login_mechanism: Gsasl_mechanism =
    unsafe {
        {
            let mut init =
                Gsasl_mechanism{name:
                                    b"LOGIN\x00" as *const u8 as
                                        *const libc::c_char,
                                client:
                                    {
                                        let mut init =
                                            Gsasl_mechanism_functions{init:
                                                                          None,
                                                                      done:
                                                                          None,
                                                                      start:
                                                                          Some(_gsasl_login_client_start
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut *mut libc::c_void)
                                                                                       ->
                                                                                           libc::c_int),
                                                                      step:
                                                                          Some(_gsasl_login_client_step
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
                                                                          Some(_gsasl_login_client_finish
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
                                                                          Some(_gsasl_login_server_start
                                                                                   as
                                                                                   unsafe extern "C" fn(_:
                                                                                                            *mut Gsasl_session,
                                                                                                        _:
                                                                                                            *mut *mut libc::c_void)
                                                                                       ->
                                                                                           libc::c_int),
                                                                      step:
                                                                          Some(_gsasl_login_server_step
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
                                                                          Some(_gsasl_login_server_finish
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
