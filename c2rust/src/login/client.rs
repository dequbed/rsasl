use ::libc;
extern "C" {
    pub type Gsasl_session;
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
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    #[no_mangle]
    fn gsasl_property_get(sctx: *mut Gsasl_session, prop: Gsasl_property)
     -> *const libc::c_char;
}
pub type size_t = libc::c_ulong;
pub type C2RustUnnamed = libc::c_uint;
pub const GSASL_GSSAPI_RELEASE_OID_SET_ERROR: C2RustUnnamed = 64;
pub const GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR: C2RustUnnamed = 63;
pub const GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR: C2RustUnnamed = 62;
pub const GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR: C2RustUnnamed = 61;
pub const GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR: C2RustUnnamed = 60;
pub const GSASL_SECURID_SERVER_NEED_NEW_PIN: C2RustUnnamed = 49;
pub const GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE: C2RustUnnamed = 48;
pub const GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR: C2RustUnnamed = 45;
pub const GSASL_GSSAPI_DISPLAY_NAME_ERROR: C2RustUnnamed = 44;
pub const GSASL_GSSAPI_ACQUIRE_CRED_ERROR: C2RustUnnamed = 43;
pub const GSASL_GSSAPI_WRAP_ERROR: C2RustUnnamed = 42;
pub const GSASL_GSSAPI_UNWRAP_ERROR: C2RustUnnamed = 41;
pub const GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR: C2RustUnnamed = 40;
pub const GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR: C2RustUnnamed = 39;
pub const GSASL_GSSAPI_IMPORT_NAME_ERROR: C2RustUnnamed = 38;
pub const GSASL_GSSAPI_RELEASE_BUFFER_ERROR: C2RustUnnamed = 37;
pub const GSASL_NO_OPENID20_REDIRECT_URL: C2RustUnnamed = 68;
pub const GSASL_NO_SAML20_REDIRECT_URL: C2RustUnnamed = 67;
pub const GSASL_NO_SAML20_IDP_IDENTIFIER: C2RustUnnamed = 66;
pub const GSASL_NO_CB_TLS_UNIQUE: C2RustUnnamed = 65;
pub const GSASL_NO_HOSTNAME: C2RustUnnamed = 59;
pub const GSASL_NO_SERVICE: C2RustUnnamed = 58;
pub const GSASL_NO_PIN: C2RustUnnamed = 57;
pub const GSASL_NO_PASSCODE: C2RustUnnamed = 56;
pub const GSASL_NO_PASSWORD: C2RustUnnamed = 55;
pub const GSASL_NO_AUTHZID: C2RustUnnamed = 54;
pub const GSASL_NO_AUTHID: C2RustUnnamed = 53;
pub const GSASL_NO_ANONYMOUS_TOKEN: C2RustUnnamed = 52;
pub const GSASL_NO_CALLBACK: C2RustUnnamed = 51;
pub const GSASL_NO_SERVER_CODE: C2RustUnnamed = 36;
pub const GSASL_NO_CLIENT_CODE: C2RustUnnamed = 35;
pub const GSASL_INTEGRITY_ERROR: C2RustUnnamed = 33;
pub const GSASL_AUTHENTICATION_ERROR: C2RustUnnamed = 31;
pub const GSASL_MECHANISM_PARSE_ERROR: C2RustUnnamed = 30;
pub const GSASL_SASLPREP_ERROR: C2RustUnnamed = 29;
pub const GSASL_CRYPTO_ERROR: C2RustUnnamed = 9;
pub const GSASL_BASE64_ERROR: C2RustUnnamed = 8;
pub const GSASL_MALLOC_ERROR: C2RustUnnamed = 7;
pub const GSASL_MECHANISM_CALLED_TOO_MANY_TIMES: C2RustUnnamed = 3;
pub const GSASL_UNKNOWN_MECHANISM: C2RustUnnamed = 2;
pub const GSASL_NEEDS_MORE: C2RustUnnamed = 1;
pub const GSASL_OK: C2RustUnnamed = 0;
pub type Gsasl_property = libc::c_uint;
pub const GSASL_VALIDATE_OPENID20: Gsasl_property = 506;
pub const GSASL_VALIDATE_SAML20: Gsasl_property = 505;
pub const GSASL_VALIDATE_SECURID: Gsasl_property = 504;
pub const GSASL_VALIDATE_GSSAPI: Gsasl_property = 503;
pub const GSASL_VALIDATE_ANONYMOUS: Gsasl_property = 502;
pub const GSASL_VALIDATE_EXTERNAL: Gsasl_property = 501;
pub const GSASL_VALIDATE_SIMPLE: Gsasl_property = 500;
pub const GSASL_OPENID20_AUTHENTICATE_IN_BROWSER: Gsasl_property = 251;
pub const GSASL_SAML20_AUTHENTICATE_IN_BROWSER: Gsasl_property = 250;
pub const GSASL_OPENID20_OUTCOME_DATA: Gsasl_property = 22;
pub const GSASL_OPENID20_REDIRECT_URL: Gsasl_property = 21;
pub const GSASL_SAML20_REDIRECT_URL: Gsasl_property = 20;
pub const GSASL_SAML20_IDP_IDENTIFIER: Gsasl_property = 19;
pub const GSASL_CB_TLS_UNIQUE: Gsasl_property = 18;
pub const GSASL_SCRAM_STOREDKEY: Gsasl_property = 24;
pub const GSASL_SCRAM_SERVERKEY: Gsasl_property = 23;
pub const GSASL_SCRAM_SALTED_PASSWORD: Gsasl_property = 17;
pub const GSASL_SCRAM_SALT: Gsasl_property = 16;
pub const GSASL_SCRAM_ITER: Gsasl_property = 15;
pub const GSASL_QOP: Gsasl_property = 14;
pub const GSASL_QOPS: Gsasl_property = 13;
pub const GSASL_DIGEST_MD5_HASHED_PASSWORD: Gsasl_property = 12;
pub const GSASL_REALM: Gsasl_property = 11;
pub const GSASL_PIN: Gsasl_property = 10;
pub const GSASL_SUGGESTED_PIN: Gsasl_property = 9;
pub const GSASL_PASSCODE: Gsasl_property = 8;
pub const GSASL_GSSAPI_DISPLAY_NAME: Gsasl_property = 7;
pub const GSASL_HOSTNAME: Gsasl_property = 6;
pub const GSASL_SERVICE: Gsasl_property = 5;
pub const GSASL_ANONYMOUS_TOKEN: Gsasl_property = 4;
pub const GSASL_PASSWORD: Gsasl_property = 3;
pub const GSASL_AUTHZID: Gsasl_property = 2;
pub const GSASL_AUTHID: Gsasl_property = 1;
/* client.c --- Non-standard SASL mechanism LOGIN, client side.
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
/* Get malloc, free. */
/* Get strlen. */
/* Get specification. */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _Gsasl_login_client_state {
    pub step: libc::c_int,
}
#[no_mangle]
pub unsafe extern "C" fn _gsasl_login_client_start(mut sctx:
                                                       *mut Gsasl_session,
                                                   mut mech_data:
                                                       *mut *mut libc::c_void)
 -> libc::c_int {
    let mut state: *mut _Gsasl_login_client_state =
        0 as *mut _Gsasl_login_client_state;
    state =
        malloc(::std::mem::size_of::<_Gsasl_login_client_state>() as
                   libc::c_ulong) as *mut _Gsasl_login_client_state;
    if state.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    (*state).step = 0 as libc::c_int;
    *mech_data = state as *mut libc::c_void;
    return GSASL_OK as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn _gsasl_login_client_step(mut sctx:
                                                      *mut Gsasl_session,
                                                  mut mech_data:
                                                      *mut libc::c_void,
                                                  mut input:
                                                      *const libc::c_char,
                                                  mut input_len: size_t,
                                                  mut output:
                                                      *mut *mut libc::c_char,
                                                  mut output_len: *mut size_t)
 -> libc::c_int {
    let mut state: *mut _Gsasl_login_client_state =
        mech_data as *mut _Gsasl_login_client_state;
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    let mut res: libc::c_int = 0;
    match (*state).step {
        0 => {
            p = gsasl_property_get(sctx, GSASL_AUTHID);
            if p.is_null() { return GSASL_NO_AUTHID as libc::c_int }
            *output = strdup(p);
            *output_len = strlen(p);
            (*state).step += 1;
            res = GSASL_NEEDS_MORE as libc::c_int
        }
        1 => {
            p = gsasl_property_get(sctx, GSASL_PASSWORD);
            if p.is_null() { return GSASL_NO_PASSWORD as libc::c_int }
            *output = strdup(p);
            if (*output).is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            *output_len = strlen(*output);
            (*state).step += 1;
            res = GSASL_OK as libc::c_int
        }
        _ => { res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int }
    }
    return res;
}
/* login.h --- Prototypes for non-standard SASL mechanism LOGIN.
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
#[no_mangle]
pub unsafe extern "C" fn _gsasl_login_client_finish(mut sctx:
                                                        *mut Gsasl_session,
                                                    mut mech_data:
                                                        *mut libc::c_void) {
    let mut state: *mut _Gsasl_login_client_state =
        mech_data as *mut _Gsasl_login_client_state;
    if state.is_null() { return }
    rpl_free(state as *mut libc::c_void);
}
