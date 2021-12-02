use ::libc;
extern "C" {
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Gsasl {
    pub n_client_mechs: size_t,
    pub client_mechs: *mut Gsasl_mechanism,
    pub n_server_mechs: size_t,
    pub server_mechs: *mut Gsasl_mechanism,
    pub cb: Gsasl_callback_function,
    pub application_hook: *mut libc::c_void,
}
pub type Gsasl_callback_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl, _: *mut Gsasl_session,
                                _: Gsasl_property) -> libc::c_int>;
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
/* internal.h --- Internal header with hidden library handle structures.
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
/* Get specifications. */
/* Get malloc, free, ... */
/* Get strlen, strcpy, ... */
/* Main library handle. */
/* Callback. */
/* Per-session library handle. */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Gsasl_session {
    pub ctx: *mut Gsasl,
    pub clientp: libc::c_int,
    pub mech: *mut Gsasl_mechanism,
    pub mech_data: *mut libc::c_void,
    pub application_hook: *mut libc::c_void,
    pub anonymous_token: *mut libc::c_char,
    pub authid: *mut libc::c_char,
    pub authzid: *mut libc::c_char,
    pub password: *mut libc::c_char,
    pub passcode: *mut libc::c_char,
    pub pin: *mut libc::c_char,
    pub suggestedpin: *mut libc::c_char,
    pub service: *mut libc::c_char,
    pub hostname: *mut libc::c_char,
    pub gssapi_display_name: *mut libc::c_char,
    pub realm: *mut libc::c_char,
    pub digest_md5_hashed_password: *mut libc::c_char,
    pub qops: *mut libc::c_char,
    pub qop: *mut libc::c_char,
    pub scram_iter: *mut libc::c_char,
    pub scram_salt: *mut libc::c_char,
    pub scram_salted_password: *mut libc::c_char,
    pub scram_serverkey: *mut libc::c_char,
    pub scram_storedkey: *mut libc::c_char,
    pub cb_tls_unique: *mut libc::c_char,
    pub saml20_idp_identifier: *mut libc::c_char,
    pub saml20_redirect_url: *mut libc::c_char,
    pub openid20_redirect_url: *mut libc::c_char,
    pub openid20_outcome_data: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Gsasl_mechanism {
    pub name: *const libc::c_char,
    pub client: Gsasl_mechanism_functions,
    pub server: Gsasl_mechanism_functions,
}
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
pub type Gsasl_code_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl_session, _: *mut libc::c_void,
                                _: *const libc::c_char, _: size_t,
                                _: *mut *mut libc::c_char, _: *mut size_t)
               -> libc::c_int>;
pub type Gsasl_finish_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl_session, _: *mut libc::c_void)
               -> ()>;
pub type Gsasl_step_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl_session, _: *mut libc::c_void,
                                _: *const libc::c_char, _: size_t,
                                _: *mut *mut libc::c_char, _: *mut size_t)
               -> libc::c_int>;
pub type Gsasl_start_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl_session,
                                _: *mut *mut libc::c_void) -> libc::c_int>;
pub type Gsasl_done_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl) -> ()>;
pub type Gsasl_init_function
    =
    Option<unsafe extern "C" fn(_: *mut Gsasl) -> libc::c_int>;
/* xcode.c --- Encode and decode application payload in libgsasl session.
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
unsafe extern "C" fn _gsasl_code(mut sctx: *mut Gsasl_session,
                                 mut code: Gsasl_code_function,
                                 mut input: *const libc::c_char,
                                 mut input_len: size_t,
                                 mut output: *mut *mut libc::c_char,
                                 mut output_len: *mut size_t) -> libc::c_int {
    if code.is_none() {
        *output_len = input_len;
        *output = malloc(*output_len) as *mut libc::c_char;
        if (*output).is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
        memcpy(*output as *mut libc::c_void, input as *const libc::c_void,
               input_len);
        return GSASL_OK as libc::c_int
    }
    return code.expect("non-null function pointer")(sctx, (*sctx).mech_data,
                                                    input, input_len, output,
                                                    output_len);
}
/* *
 * gsasl_encode:
 * @sctx: libgsasl session handle.
 * @input: input byte array.
 * @input_len: size of input byte array.
 * @output: newly allocated output byte array.
 * @output_len: pointer to output variable with size of output byte array.
 *
 * Encode data according to negotiated SASL mechanism.  This might mean
 * that data is integrity or privacy protected.
 *
 * The @output buffer is allocated by this function, and it is the
 * responsibility of caller to deallocate it by calling
 * gsasl_free(@output).
 *
 * Return value: Returns %GSASL_OK if encoding was successful,
 *   otherwise an error code.
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_encode(mut sctx: *mut Gsasl_session,
                                      mut input: *const libc::c_char,
                                      mut input_len: size_t,
                                      mut output: *mut *mut libc::c_char,
                                      mut output_len: *mut size_t)
 -> libc::c_int {
    let mut code: Gsasl_code_function = None;
    if (*sctx).clientp != 0 {
        code = (*(*sctx).mech).client.encode
    } else { code = (*(*sctx).mech).server.encode }
    return _gsasl_code(sctx, code, input, input_len, output, output_len);
}
/* gsasl.h --- Header file for GNU SASL Library.
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
 * SECTION:gsasl
 * @title: gsasl.h
 * @short_description: main library interfaces
 *
 * The main library interfaces are declared in gsasl.h.
 */
/* size_t */
/* Get version symbols. */
/* *
 * GSASL_API:
 *
 * Symbol holding shared library API visibility decorator.
 *
 * This is used internally by the library header file and should never
 * be used or modified by the application.
 *
 * https://www.gnu.org/software/gnulib/manual/html_node/Exported-Symbols-of-Shared-Libraries.html
 */
/* RFC 2222: SASL mechanisms are named by strings, from 1 to 20
   * characters in length, consisting of upper-case letters, digits,
   * hyphens, and/or underscores.  SASL mechanism names must be
   * registered with the IANA.
   */
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
/* Mechanism specific errors. */
/* When adding new values, note that integers are not necessarily
         assigned monotonously increasingly. */
/* *
   * Gsasl_qop:
   * @GSASL_QOP_AUTH: Authentication only.
   * @GSASL_QOP_AUTH_INT: Authentication and integrity.
   * @GSASL_QOP_AUTH_CONF: Authentication, integrity and confidentiality.
   *
   * Quality of Protection types (DIGEST-MD5 and GSSAPI).  The
   * integrity and confidentiality values is about application data
   * wrapping.  We recommend that you use @GSASL_QOP_AUTH with TLS as
   * that combination is generally more secure and have better chance
   * of working than the integrity/confidentiality layers of SASL.
   */
/* *
   * Gsasl_saslprep_flags:
   * @GSASL_ALLOW_UNASSIGNED: Allow unassigned code points.
   *
   * Flags for the SASLprep function, see gsasl_saslprep().  For
   * background, see the GNU Libidn documentation.
   */
/* *
   * Gsasl:
   *
   * Handle to global library context.
   */
/* *
   * Gsasl_session:
   *
   * Handle to SASL session context.
   */
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
/* Information properties, e.g., username. */
/* Client callbacks. */
/* Server validation callback properties. */
/* *
   * Gsasl_callback_function:
   * @ctx: libgsasl handle.
   * @sctx: session handle, may be NULL.
   * @prop: enumerated value of Gsasl_property type.
   *
   * Prototype of function that the application should implement.  Use
   * gsasl_callback_set() to inform the library about your callback
   * function.
   *
   * It is called by the SASL library when it need some information
   * from the application.  Depending on the value of @prop, it should
   * either set some property (e.g., username or password) using
   * gsasl_property_set(), or it should extract some properties (e.g.,
   * authentication and authorization identities) using
   * gsasl_property_fast() and use them to make a policy decision,
   * perhaps returning GSASL_AUTHENTICATION_ERROR or GSASL_OK
   * depending on whether the policy permitted the operation.
   *
   * Return value: Any valid return code, the interpretation of which
   *   depend on the @prop value.
   *
   * Since: 0.2.0
   **/
/* Library entry and exit points: version.c, init.c, done.c */
/* Callback handling: callback.c */
/* Property handling: property.c */
/* Mechanism handling: listmech.c, supportp.c, suggest.c */
/* Authentication functions: xstart.c, xstep.c, xfinish.c */
/* Session functions: xcode.c, mechname.c */
/* *
 * gsasl_decode:
 * @sctx: libgsasl session handle.
 * @input: input byte array.
 * @input_len: size of input byte array.
 * @output: newly allocated output byte array.
 * @output_len: pointer to output variable with size of output byte array.
 *
 * Decode data according to negotiated SASL mechanism.  This might mean
 * that data is integrity or privacy protected.
 *
 * The @output buffer is allocated by this function, and it is the
 * responsibility of caller to deallocate it by calling
 * gsasl_free(@output).
 *
 * Return value: Returns %GSASL_OK if encoding was successful,
 *   otherwise an error code.
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_decode(mut sctx: *mut Gsasl_session,
                                      mut input: *const libc::c_char,
                                      mut input_len: size_t,
                                      mut output: *mut *mut libc::c_char,
                                      mut output_len: *mut size_t)
 -> libc::c_int {
    let mut code: Gsasl_code_function = None;
    if (*sctx).clientp != 0 {
        code = (*(*sctx).mech).client.decode
    } else { code = (*(*sctx).mech).server.decode }
    return _gsasl_code(sctx, code, input, input_len, output, output_len);
}
