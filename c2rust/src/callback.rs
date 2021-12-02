use ::libc;
use libc::size_t;
use crate::consts::{GSASL_NO_CALLBACK, Gsasl_property};
use crate::gsasl::{Gsasl, Gsasl_callback_function, Gsasl_session};

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
pub unsafe extern "C" fn gsasl_callback_set(mut ctx: *mut Gsasl,
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
pub unsafe extern "C" fn gsasl_callback(mut ctx: *mut Gsasl,
                                        mut sctx: *mut Gsasl_session,
                                        mut prop: Gsasl_property)
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
/* *
 * gsasl_callback_hook_set:
 * @ctx: libgsasl handle.
 * @hook: opaque pointer to application specific data.
 *
 * Store application specific data in the libgsasl handle.
 *
 * The application data can be later (for instance, inside a callback)
 * be retrieved by calling gsasl_callback_hook_get().  This is
 * normally used by the application to maintain a global state between
 * the main program and callbacks.
 *
 * Since: 0.2.0
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_callback_hook_set(mut ctx: *mut Gsasl,
                                                 mut hook:
                                                     *mut libc::c_void) {
    (*ctx).application_hook = hook;
}
/* *
 * gsasl_callback_hook_get:
 * @ctx: libgsasl handle.
 *
 * Retrieve application specific data from libgsasl handle.
 *
 * The application data is set using gsasl_callback_hook_set().  This
 * is normally used by the application to maintain a global state
 * between the main program and callbacks.
 *
 * Return value: Returns the application specific data, or NULL.
 *
 * Since: 0.2.0
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_callback_hook_get(mut ctx: *mut Gsasl)
 -> *mut libc::c_void {
    return (*ctx).application_hook;
}
/* *
 * gsasl_session_hook_set:
 * @sctx: libgsasl session handle.
 * @hook: opaque pointer to application specific data.
 *
 * Store application specific data in the libgsasl session handle.
 *
 * The application data can be later (for instance, inside a callback)
 * be retrieved by calling gsasl_session_hook_get().  This is normally
 * used by the application to maintain a per-session state between the
 * main program and callbacks.
 *
 * Since: 0.2.14
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_session_hook_set(mut sctx: *mut Gsasl_session,
                                                mut hook: *mut libc::c_void) {
    (*sctx).application_hook = hook;
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
/* *
 * gsasl_session_hook_get:
 * @sctx: libgsasl session handle.
 *
 * Retrieve application specific data from libgsasl session handle.
 *
 * The application data is set using gsasl_callback_hook_set().  This
 * is normally used by the application to maintain a per-session state
 * between the main program and callbacks.
 *
 * Return value: Returns the application specific data, or NULL.
 *
 * Since: 0.2.14
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_session_hook_get(mut sctx: *mut Gsasl_session)
 -> *mut libc::c_void {
    return (*sctx).application_hook;
}
