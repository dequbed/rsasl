use ::libc;
use libc::size_t;
use crate::gsasl::consts::GSASL_OK;
use crate::gsasl::gc::Gc_rc;
use crate::gsasl::mechtools::{Gsasl_hash, GSASL_HASH_SHA1_SIZE, GSASL_HASH_SHA256_SIZE};
use crate::gsasl::saslprep::{GSASL_ALLOW_UNASSIGNED, Gsasl_saslprep_flags};

extern "C" {
    fn gsasl_saslprep(in_0: *const libc::c_char, flags: Gsasl_saslprep_flags,
                      out: *mut *mut libc::c_char,
                      stringpreprc: *mut libc::c_int) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> size_t;
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
    /* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* A GNU-like <stdlib.h>.

   Copyright (C) 1995, 2001-2004, 2006-2021 Free Software Foundation, Inc.

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
    fn rpl_free(ptr: *mut libc::c_void);
    fn _gsasl_hash(hash: Gsasl_hash, in_0: *const libc::c_char, inlen: size_t,
                   out: *mut libc::c_char) -> libc::c_int;
    fn _gsasl_hmac(hash: Gsasl_hash, key: *const libc::c_char, keylen: size_t,
                   in_0: *const libc::c_char, inlen: size_t,
                   outhash: *mut libc::c_char) -> libc::c_int;
    fn _gsasl_pbkdf2(hash: Gsasl_hash, password: *const libc::c_char,
                     passwordlen: size_t, salt: *const libc::c_char,
                     saltlen: size_t, c: libc::c_uint, dk: *mut libc::c_char,
                     dklen: size_t) -> libc::c_int;
    /* Randomness. */
    fn gc_nonce(data: *mut libc::c_char, datalen: size_t) -> Gc_rc;
    fn gc_random(data: *mut libc::c_char, datalen: size_t) -> Gc_rc;
}
/* gc.h --- Header file for implementation agnostic crypto wrapper API.
 * Copyright (C) 2002-2005, 2007-2008, 2011-2021 Free Software Foundation, Inc.
 *
 * This file is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */
/* crypto.c --- Simple crypto wrappers for applications.
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
 * gsasl_nonce:
 * @data: output array to be filled with unpredictable random data.
 * @datalen: size of output array.
 *
 * Store unpredictable data of given size in the provided buffer.
 *
 * Return value: Returns %GSASL_OK iff successful.
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_nonce(mut data: *mut libc::c_char,
                                     mut datalen: size_t) -> libc::c_int {
    return gc_nonce(data, datalen) as libc::c_int;
}
/* *
 * gsasl_random:
 * @data: output array to be filled with strong random data.
 * @datalen: size of output array.
 *
 * Store cryptographically strong random data of given size in the
 * provided buffer.
 *
 * Return value: Returns %GSASL_OK iff successful.
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_random(mut data: *mut libc::c_char,
                                      mut datalen: size_t) -> libc::c_int {
    return gc_random(data, datalen) as libc::c_int;
}
/* *
 * gsasl_hash_length:
 * @hash: a %Gsasl_hash element, e.g., #GSASL_HASH_SHA256.
 *
 * Return the digest output size for hash function @hash.  For
 * example, gsasl_hash_length(GSASL_HASH_SHA256) returns
 * GSASL_HASH_SHA256_SIZE which is 32.
 *
 * Returns: size of supplied %Gsasl_hash element.
 *
 * Since: 1.10
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_hash_length(mut hash: Gsasl_hash) -> size_t {
    match hash as libc::c_uint {
        2 => { return GSASL_HASH_SHA1_SIZE as libc::c_int as size_t }
        3 => { return GSASL_HASH_SHA256_SIZE as libc::c_int as size_t }
        _ => { }
    }
    return 0 as libc::c_int as size_t;
}
/* *
 * gsasl_scram_secrets_from_salted_password:
 * @hash: a %Gsasl_hash element, e.g., #GSASL_HASH_SHA256.
 * @salted_password: input array with salted password.
 * @client_key: pre-allocated output array with derived client key.
 * @server_key: pre-allocated output array with derived server key.
 * @stored_key: pre-allocated output array with derived stored key.
 *
 * Helper function to derive SCRAM ClientKey/ServerKey/StoredKey.  The
 * @client_key, @server_key, and @stored_key buffers must have room to
 * hold digest for given @hash, use #GSASL_HASH_MAX_SIZE which is
 * sufficient for all hashes.
 *
 * Return value: Returns %GSASL_OK if successful, or error code.
 *
 * Since: 1.10
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_scram_secrets_from_salted_password(mut hash:
                                                                      Gsasl_hash,
                                                                  mut salted_password:
                                                                      *const libc::c_char,
                                                                  mut client_key:
                                                                      *mut libc::c_char,
                                                                  mut server_key:
                                                                      *mut libc::c_char,
                                                                  mut stored_key:
                                                                      *mut libc::c_char)
 -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut hashlen: size_t = gsasl_hash_length(hash);
    /* ClientKey */
    res =
        _gsasl_hmac(hash, salted_password, hashlen,
                    b"Client Key\x00" as *const u8 as *const libc::c_char,
                    strlen(b"Client Key\x00" as *const u8 as
                               *const libc::c_char) as usize, client_key);
    if res != GSASL_OK as libc::c_int { return res }
    /* StoredKey */
    res = _gsasl_hash(hash, client_key, hashlen, stored_key);
    if res != GSASL_OK as libc::c_int { return res }
    /* ServerKey */
    res =
        _gsasl_hmac(hash, salted_password, hashlen,
                    b"Server Key\x00" as *const u8 as *const libc::c_char,
                    strlen(b"Server Key\x00" as *const u8 as
                               *const libc::c_char) as usize, server_key);
    if res != GSASL_OK as libc::c_int { return res }
    return GSASL_OK as libc::c_int;
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
/* Error handling: error.c */
/* Internationalized string processing: stringprep.c */
/* Crypto functions: crypto.c */
/* *
   * Gsasl_hash:
   * @GSASL_HASH_SHA1: Hash function SHA-1.
   * @GSASL_HASH_SHA256: Hash function SHA-256.
   *
   * Hash functions.  You may use gsasl_hash_length() to get the
   * output size of a hash function.
   *
   * Currently only used as parameter to
   * gsasl_scram_secrets_from_salted_password() and
   * gsasl_scram_secrets_from_password() to specify for which SCRAM
   * mechanism to prepare secrets for.
   *
   * Since: 1.10
   */
/* Hash algorithm identifiers. */
/* *
   * Gsasl_hash_length:
   * @GSASL_HASH_SHA1_SIZE: Output size of hash function SHA-1.
   * @GSASL_HASH_SHA256_SIZE: Output size of hash function SHA-256.
   * @GSASL_HASH_MAX_SIZE: Maximum output size of any %Gsasl_hash_length.
   *
   * Identifiers specifying the output size of hash functions.
   *
   * These can be used when statically allocating the buffers needed
   * for, e.g., gsasl_scram_secrets_from_password().
   *
   * Since: 1.10
   */
/* Output sizes of hashes. */
/* *
 * gsasl_scram_secrets_from_password:
 * @hash: a %Gsasl_hash element, e.g., #GSASL_HASH_SHA256.
 * @password: input parameter with password.
 * @iteration_count: number of PBKDF2 rounds to apply.
 * @salt: input character array of @saltlen length with salt for PBKDF2.
 * @saltlen: length of @salt.
 * @salted_password: pre-allocated output array with derived salted password.
 * @client_key: pre-allocated output array with derived client key.
 * @server_key: pre-allocated output array with derived server key.
 * @stored_key: pre-allocated output array with derived stored key.
 *
 * Helper function to generate SCRAM secrets from a password.  The
 * @salted_password, @client_key, @server_key, and @stored_key buffers
 * must have room to hold digest for given @hash, use
 * #GSASL_HASH_MAX_SIZE which is sufficient for all hashes.
 *
 * Return value: Returns %GSASL_OK if successful, or error code.
 *
 * Since: 1.10
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_scram_secrets_from_password(mut hash:
                                                               Gsasl_hash,
                                                           mut password:
                                                               *const libc::c_char,
                                                           mut iteration_count:
                                                               libc::c_uint,
                                                           mut salt:
                                                               *const libc::c_char,
                                                           mut saltlen:
                                                               size_t,
                                                           mut salted_password:
                                                               *mut libc::c_char,
                                                           mut client_key:
                                                               *mut libc::c_char,
                                                           mut server_key:
                                                               *mut libc::c_char,
                                                           mut stored_key:
                                                               *mut libc::c_char)
 -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut preppass: *mut libc::c_char = 0 as *mut libc::c_char;
    res =
        gsasl_saslprep(password, GSASL_ALLOW_UNASSIGNED, &mut preppass,
                       0 as *mut libc::c_int);
    if res != GSASL_OK as libc::c_int { return res }
    res =
        _gsasl_pbkdf2(hash, preppass, strlen(preppass) as usize, salt, saltlen,
                      iteration_count, salted_password,
                      0 as libc::c_int as size_t);
    rpl_free(preppass as *mut libc::c_void);
    if res != GSASL_OK as libc::c_int { return res }
    return gsasl_scram_secrets_from_salted_password(hash, salted_password,
                                                    client_key, server_key,
                                                    stored_key);
}
