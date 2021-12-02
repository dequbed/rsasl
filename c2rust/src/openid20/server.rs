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
    fn gsasl_callback(ctx: *mut Gsasl, sctx: *mut Gsasl_session,
                      prop: Gsasl_property) -> libc::c_int;
    /* Property handling: property.c */
    #[no_mangle]
    fn gsasl_property_set(sctx: *mut Gsasl_session, prop: Gsasl_property,
                          data: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn gsasl_property_set_raw(sctx: *mut Gsasl_session, prop: Gsasl_property,
                              data: *const libc::c_char, len: size_t)
     -> libc::c_int;
    #[no_mangle]
    fn gsasl_property_get(sctx: *mut Gsasl_session, prop: Gsasl_property)
     -> *const libc::c_char;
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    #[no_mangle]
    fn rpl_free(_: *mut libc::c_void);
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    /* mechtools.h --- Helper functions available for use by any mechanism.
 * Copyright (C) 2010-2021 Simon Josefsson
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
    /* Get bool. */
    #[no_mangle]
    fn _gsasl_parse_gs2_header(data: *const libc::c_char, len: size_t,
                               authzid: *mut *mut libc::c_char,
                               headerlen: *mut size_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
/* *
   * Gsasl_rc:
   * @GSASL_OK: Successful return code, guaranteed to be always 0.
   * @GSASL_NEEDS_MORE: Mechanism expects another round-trip.
   * @GSASL_UNKNOWN_MECHANISM: Application requested an unknown mechanism.
   * @GSASL_MECHANISM_CALLED_TOO_MANY_TIMES: Application requested too
   *   many round trips from mechanism.
   * @GSASL_MALLOC_ERROR: Memory allocation failed.
   * @GSASL_BASE64_ERROR: Base64 encoding/decoding failed.
   * @GSASL_CRYPTO_ERROR: Cryptographic error.
   * @GSASL_SASLPREP_ERROR: Failed to prepare internationalized string.
   * @GSASL_MECHANISM_PARSE_ERROR: Mechanism could not parse input.
   * @GSASL_AUTHENTICATION_ERROR: Authentication has failed.
   * @GSASL_INTEGRITY_ERROR: Application data integrity check failed.
   * @GSASL_NO_CLIENT_CODE: Library was built with client functionality.
   * @GSASL_NO_SERVER_CODE: Library was built with server functionality.
   * @GSASL_NO_CALLBACK: Application did not provide a callback.
   * @GSASL_NO_ANONYMOUS_TOKEN: Could not get required anonymous token.
   * @GSASL_NO_AUTHID: Could not get required authentication
   *   identity (username).
   * @GSASL_NO_AUTHZID: Could not get required authorization identity.
   * @GSASL_NO_PASSWORD: Could not get required password.
   * @GSASL_NO_PASSCODE: Could not get required SecurID PIN.
   * @GSASL_NO_PIN: Could not get required SecurID PIN.
   * @GSASL_NO_SERVICE: Could not get required service name.
   * @GSASL_NO_HOSTNAME: Could not get required hostname.
   * @GSASL_NO_CB_TLS_UNIQUE: Could not get required tls-unique CB.
   * @GSASL_NO_SAML20_IDP_IDENTIFIER: Could not get required SAML IdP.
   * @GSASL_NO_SAML20_REDIRECT_URL: Could not get required SAML
   *   redirect URL.
   * @GSASL_NO_OPENID20_REDIRECT_URL: Could not get required OpenID
   *   redirect URL.
   * @GSASL_GSSAPI_RELEASE_BUFFER_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_IMPORT_NAME_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_UNWRAP_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_WRAP_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_ACQUIRE_CRED_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_DISPLAY_NAME_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR: An unsupported
   *   quality-of-protection layer was requeted.
   * @GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_RELEASE_OID_SET_ERROR: GSS-API library call error.
   * @GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE: SecurID mechanism
   *   needs an additional passcode.
   * @GSASL_SECURID_SERVER_NEED_NEW_PIN: SecurID mechanism
   *   needs an new PIN.
   *
   * Error codes for library functions.
   */
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
/* When adding new values, note that integers are not necessarily
         assigned monotonously increasingly. */
/* Mechanism specific errors. */
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
/* *
   * Gsasl_property:
   * @GSASL_AUTHID: Authentication identity (username).
   * @GSASL_AUTHZID: Authorization identity.
   * @GSASL_PASSWORD: Password.
   * @GSASL_ANONYMOUS_TOKEN: Anonymous identifier.
   * @GSASL_SERVICE: Service name
   * @GSASL_HOSTNAME: Host name.
   * @GSASL_GSSAPI_DISPLAY_NAME: GSS-API credential principal name.
   * @GSASL_PASSCODE: SecurID passcode.
   * @GSASL_SUGGESTED_PIN: SecurID suggested PIN.
   * @GSASL_PIN: SecurID PIN.
   * @GSASL_REALM: User realm.
   * @GSASL_DIGEST_MD5_HASHED_PASSWORD: Pre-computed hashed DIGEST-MD5
   *   password, to avoid storing passwords in the clear.
   * @GSASL_QOPS: Set of quality-of-protection values.
   * @GSASL_QOP: Quality-of-protection value.
   * @GSASL_SCRAM_ITER: Number of iterations in password-to-key hashing.
   * @GSASL_SCRAM_SALT: Salt for password-to-key hashing.
   * @GSASL_SCRAM_SALTED_PASSWORD: Hex-encoded hashed/salted password.
   * @GSASL_SCRAM_SERVERKEY: Hex-encoded SCRAM ServerKey derived
   *   from users' passowrd.
   * @GSASL_SCRAM_STOREDKEY: Hex-encoded SCRAM StoredKey derived
   *   from users' passowrd.
   * @GSASL_CB_TLS_UNIQUE: Base64 encoded tls-unique channel binding.
   * @GSASL_SAML20_IDP_IDENTIFIER: SAML20 user IdP URL.
   * @GSASL_SAML20_REDIRECT_URL: SAML 2.0 URL to access in browser.
   * @GSASL_OPENID20_REDIRECT_URL: OpenID 2.0 URL to access in browser.
   * @GSASL_OPENID20_OUTCOME_DATA: OpenID 2.0 authentication outcome data.
   * @GSASL_SAML20_AUTHENTICATE_IN_BROWSER: Request to perform SAML 2.0
   *   authentication in browser.
   * @GSASL_OPENID20_AUTHENTICATE_IN_BROWSER: Request to perform OpenID 2.0
   *   authentication in browser.
   * @GSASL_VALIDATE_SIMPLE: Request for simple validation.
   * @GSASL_VALIDATE_EXTERNAL: Request for validation of EXTERNAL.
   * @GSASL_VALIDATE_ANONYMOUS: Request for validation of ANONYMOUS.
   * @GSASL_VALIDATE_GSSAPI: Request for validation of GSSAPI/GS2.
   * @GSASL_VALIDATE_SECURID: Reqest for validation of SecurID.
   * @GSASL_VALIDATE_SAML20: Reqest for validation of SAML20.
   * @GSASL_VALIDATE_OPENID20: Reqest for validation of OpenID 2.0 login.
   *
   * Callback/property types.
   */
pub type Gsasl_property = libc::c_uint;
pub const GSASL_VALIDATE_OPENID20: Gsasl_property = 506;
pub const GSASL_VALIDATE_SAML20: Gsasl_property = 505;
pub const GSASL_VALIDATE_SECURID: Gsasl_property = 504;
pub const GSASL_VALIDATE_GSSAPI: Gsasl_property = 503;
pub const GSASL_VALIDATE_ANONYMOUS: Gsasl_property = 502;
pub const GSASL_VALIDATE_EXTERNAL: Gsasl_property = 501;
/* Server validation callback properties. */
pub const GSASL_VALIDATE_SIMPLE: Gsasl_property = 500;
pub const GSASL_OPENID20_AUTHENTICATE_IN_BROWSER: Gsasl_property = 251;
/* Client callbacks. */
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
/* Information properties, e.g., username. */
pub const GSASL_AUTHID: Gsasl_property = 1;
/* server.c --- OPENID20 mechanism, server side.
 * Copyright (C) 2011-2021 Simon Josefsson
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
/* Get strdup, strlen. */
/* Get calloc, free. */
/* Get _gsasl_parse_gs2_header. */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct openid20_server_state {
    pub step: libc::c_int,
    pub allow_error_step: libc::c_int,
}
#[no_mangle]
pub unsafe extern "C" fn _gsasl_openid20_server_start(mut sctx:
                                                          *mut Gsasl_session,
                                                      mut mech_data:
                                                          *mut *mut libc::c_void)
 -> libc::c_int {
    let mut state: *mut openid20_server_state =
        0 as *mut openid20_server_state;
    state =
        calloc(::std::mem::size_of::<openid20_server_state>() as
                   libc::c_ulong, 1 as libc::c_int as libc::c_ulong) as
            *mut openid20_server_state;
    if state.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    *mech_data = state as *mut libc::c_void;
    return GSASL_OK as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn _gsasl_openid20_server_step(mut sctx:
                                                         *mut Gsasl_session,
                                                     mut mech_data:
                                                         *mut libc::c_void,
                                                     mut input:
                                                         *const libc::c_char,
                                                     mut input_len: size_t,
                                                     mut output:
                                                         *mut *mut libc::c_char,
                                                     mut output_len:
                                                         *mut size_t)
 -> libc::c_int {
    let mut state: *mut openid20_server_state =
        mech_data as *mut openid20_server_state;
    let mut res: libc::c_int =
        GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int;
    *output_len = 0 as libc::c_int as size_t;
    *output = 0 as *mut libc::c_char;
    match (*state).step {
        0 => {
            let mut p: *const libc::c_char = 0 as *const libc::c_char;
            let mut authzid: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut headerlen: size_t = 0;
            if input_len == 0 as libc::c_int as libc::c_ulong {
                return GSASL_NEEDS_MORE as libc::c_int
            }
            res =
                _gsasl_parse_gs2_header(input, input_len, &mut authzid,
                                        &mut headerlen);
            if res != GSASL_OK as libc::c_int { return res }
            if !authzid.is_null() {
                res = gsasl_property_set(sctx, GSASL_AUTHZID, authzid);
                rpl_free(authzid as *mut libc::c_void);
                if res != GSASL_OK as libc::c_int { return res }
            }
            input = input.offset(headerlen as isize);
            input_len =
                (input_len as libc::c_ulong).wrapping_sub(headerlen) as size_t
                    as size_t;
            res =
                gsasl_property_set_raw(sctx, GSASL_AUTHID, input, input_len);
            if res != GSASL_OK as libc::c_int { return res }
            p = gsasl_property_get(sctx, GSASL_OPENID20_REDIRECT_URL);
            if p.is_null() || *p == 0 {
                return GSASL_NO_OPENID20_REDIRECT_URL as libc::c_int
            }
            *output_len = strlen(p);
            *output = malloc(*output_len) as *mut libc::c_char;
            if (*output).is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            memcpy(*output as *mut libc::c_void, p as *const libc::c_void,
                   *output_len);
            res = GSASL_NEEDS_MORE as libc::c_int;
            (*state).step += 1
        }
        1 => {
            let mut outcome_data: *const libc::c_char =
                0 as *const libc::c_char;
            if !(input_len == 1 as libc::c_int as libc::c_ulong &&
                     *input as libc::c_int == '=' as i32) {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            res =
                gsasl_callback(0 as *mut Gsasl, sctx,
                               GSASL_VALIDATE_OPENID20);
            if res != GSASL_OK as libc::c_int {
                *output =
                    strdup(b"openid.error=fail\x00" as *const u8 as
                               *const libc::c_char);
                if (*output).is_null() {
                    return GSASL_MALLOC_ERROR as libc::c_int
                }
                *output_len = strlen(*output);
                /* [RFC4422] Section 3.6 explicitly prohibits additional
	       information in an unsuccessful authentication outcome.
	       Therefore, the openid.error and openid.error_code are
	       to be sent as an additional challenge in the event of
	       an unsuccessful outcome.  In this case, as the protocol
	       is lock step, the client will follow with an additional
	       exchange containing "=", after which the server will
	       respond with an application-level outcome. */
                (*state).allow_error_step = 1 as libc::c_int;
                (*state).step += 1;
                return GSASL_NEEDS_MORE as libc::c_int
            }
            outcome_data =
                gsasl_property_get(sctx, GSASL_OPENID20_OUTCOME_DATA);
            if !outcome_data.is_null() {
                *output = strdup(outcome_data);
                if (*output).is_null() {
                    return GSASL_MALLOC_ERROR as libc::c_int
                }
                *output_len = strlen(*output)
            } else {
                *output = 0 as *mut libc::c_char;
                *output_len = 0 as libc::c_int as size_t
            }
            res = GSASL_OK as libc::c_int;
            (*state).step += 1
        }
        2 => {
            /* We only get here when the previous step signalled an error
	   to the client.  */
            if (*state).allow_error_step == 0 {
                return GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as libc::c_int
            }
            if !(input_len == 1 as libc::c_int as libc::c_ulong &&
                     *input as libc::c_int == '=' as i32) {
                return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
            }
            res = GSASL_AUTHENTICATION_ERROR as libc::c_int;
            (*state).step += 1
        }
        _ => { }
    }
    return res;
}
/* openid20.h --- Prototypes for OPENID20.
 * Copyright (C) 2011-2021 Simon Josefsson
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
pub unsafe extern "C" fn _gsasl_openid20_server_finish(mut sctx:
                                                           *mut Gsasl_session,
                                                       mut mech_data:
                                                           *mut libc::c_void) {
    let mut state: *mut openid20_server_state =
        mech_data as *mut openid20_server_state;
    if state.is_null() { return }
    rpl_free(state as *mut libc::c_void);
}
