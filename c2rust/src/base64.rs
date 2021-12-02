use ::libc;
use libc::{size_t, ptrdiff_t};
use crate::consts::*;

extern "C" {
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn base64_encode_alloc(in_0: *const libc::c_char, inlen: idx_t,
                           out: *mut *mut libc::c_char) -> idx_t;
    #[no_mangle]
    fn base64_decode_alloc_ctx(ctx: *mut base64_decode_context,
                               in_0: *const libc::c_char, inlen: idx_t,
                               out: *mut *mut libc::c_char,
                               outlen: *mut idx_t) -> bool;
    #[no_mangle]
    fn _gsasl_hex_encode(in_0: *const libc::c_char, inlen: size_t,
                         out: *mut libc::c_char);
    #[no_mangle]
    fn _gsasl_hex_decode(hexstr: *const libc::c_char, bin: *mut libc::c_char);
    #[no_mangle]
    fn _gsasl_hex_p(hexstr: *const libc::c_char) -> bool;
}
/* A type for indices and sizes.
   Copyright (C) 2020-2021 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */
/* Get ptrdiff_t.  */
/* Get PTRDIFF_MAX.  */
/* The type 'idx_t' holds an (array) index or an (object) size.
   Its implementation promotes to a signed integer type,
   which can hold the values
     0..2^63-1 (on 64-bit platforms) or
     0..2^31-1 (on 32-bit platforms).

   Why a signed integer type?

     * Security: Signed types can be checked for overflow via
       '-fsanitize=undefined', but unsigned types cannot.

     * Comparisons without surprises: ISO C99 § 6.3.1.8 specifies a few
       surprising results for comparisons, such as

           (int) -3 < (unsigned long) 7  =>  false
           (int) -3 < (unsigned int) 7   =>  false
       and on 32-bit machines:
           (long) -3 < (unsigned int) 7  =>  false

       This is surprising because the natural comparison order is by
       value in the realm of infinite-precision signed integers (ℤ).

       The best way to get rid of such surprises is to use signed types
       for numerical integer values, and use unsigned types only for
       bit masks and enums.

   Why not use 'size_t' directly?

     * Because 'size_t' is an unsigned type, and a signed type is better.
       See above.

   Why not use 'ssize_t'?

     * 'ptrdiff_t' is more portable; it is standardized by ISO C
       whereas 'ssize_t' is standardized only by POSIX.

     * 'ssize_t' is not required to be as wide as 'size_t', and some
       now-obsolete POSIX platforms had 'size_t' wider than 'ssize_t'.

     * Conversely, some now-obsolete platforms had 'ptrdiff_t' wider
       than 'size_t', which can be a win and conforms to POSIX.

   Won't this cause a problem with objects larger than PTRDIFF_MAX?

     * Typical modern or large platforms do not allocate such objects,
       so this is not much of a problem in practice; for example, you
       can safely write 'idx_t len = strlen (s);'.  To port to older
       small platforms where allocations larger than PTRDIFF_MAX could
       in theory be a problem, you can use Gnulib's ialloc module, or
       functions like ximalloc in Gnulib's xalloc module.

   Why not use 'ptrdiff_t' directly?

     * Maintainability: When reading and modifying code, it helps to know that
       a certain variable cannot have negative values.  For example, when you
       have a loop

         int n = ...;
         for (int i = 0; i < n; i++) ...

       or

         ptrdiff_t n = ...;
         for (ptrdiff_t i = 0; i < n; i++) ...

       you have to ask yourself "what if n < 0?".  Whereas in

         idx_t n = ...;
         for (idx_t i = 0; i < n; i++) ...

       you know that this case cannot happen.

       Similarly, when a programmer writes

         idx_t = ptr2 - ptr1;

       there is an implied assertion that ptr1 and ptr2 point into the same
       object and that ptr1 <= ptr2.

     * Being future-proof: In the future, range types (integers which are
       constrained to a certain range of values) may be added to C compilers
       or to the C standard.  Several programming languages (Ada, Haskell,
       Common Lisp, Pascal) already have range types.  Such range types may
       help producing good code and good warnings.  The type 'idx_t' could
       then be typedef'ed to a range type that is signed after promotion.  */
/* In the future, idx_t could be typedef'ed to a signed range type.
   The clang "extended integer types", supported in Clang 11 or newer
   <https://clang.llvm.org/docs/LanguageExtensions.html#extended-integer-types>,
   are a special case of range types.  However, these types don't support binary
   operators with plain integer types (e.g. expressions such as x > 1).
   Therefore, they don't behave like signed types (and not like unsigned types
   either).  So, we cannot use them here.  */
/* Use the signed type 'ptrdiff_t'.  */
/* Note: ISO C does not mandate that 'size_t' and 'ptrdiff_t' have the same
   size, but it is so on all platforms we have seen since 1990.  */
pub type idx_t = ptrdiff_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct base64_decode_context {
    pub i: libc::c_int,
    pub buf: [libc::c_char; 4],
}
/* base64.c --- Base64 encoding/decoding functions.
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
 * gsasl_base64_to:
 * @in: input byte array.
 * @inlen: size of input byte array.
 * @out: pointer to newly allocated base64-encoded string.
 * @outlen: pointer to size of newly allocated base64-encoded string.
 *
 * Encode data as base64.  The @out string is zero terminated, and
 * @outlen holds the length excluding the terminating zero.  The @out
 * buffer must be deallocated by the caller.
 *
 * Return value: Returns %GSASL_OK on success, or %GSASL_MALLOC_ERROR
 *   if input was too large or memory allocation fail.
 *
 * Since: 0.2.2
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_base64_to(mut in_0: *const libc::c_char,
                                         mut inlen: size_t,
                                         mut out: *mut *mut libc::c_char,
                                         mut outlen: *mut size_t)
 -> libc::c_int {
    let mut len: size_t =
        base64_encode_alloc(in_0, inlen as idx_t, out) as size_t;
    if !outlen.is_null() { *outlen = len }
    if (*out).is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    return GSASL_OK as libc::c_int;
}
/* *
 * gsasl_base64_from:
 * @in: input byte array
 * @inlen: size of input byte array
 * @out: pointer to newly allocated output byte array
 * @outlen: pointer to size of newly allocated output byte array
 *
 * Decode Base64 data.  The @out buffer must be deallocated by the
 * caller.
 *
 * Return value: Returns %GSASL_OK on success, %GSASL_BASE64_ERROR if
 *   input was invalid, and %GSASL_MALLOC_ERROR on memory allocation
 *   errors.
 *
 * Since: 0.2.2
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_base64_from(mut in_0: *const libc::c_char,
                                           mut inlen: size_t,
                                           mut out: *mut *mut libc::c_char,
                                           mut outlen: *mut size_t)
 -> libc::c_int {
    let mut ok: libc::c_int =
        base64_decode_alloc_ctx(0 as *mut base64_decode_context, in_0,
                                inlen as idx_t, out, outlen as *mut idx_t) as
            libc::c_int;
    if ok == 0 { return GSASL_BASE64_ERROR as libc::c_int }
    if (*out).is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    return GSASL_OK as libc::c_int;
}
/* *
 * gsasl_hex_to:
 * @in: input byte array.
 * @inlen: size of input byte array.
 * @out: pointer to newly allocated hex-encoded string.
 * @outlen: pointer to size of newly allocated hex-encoded string.
 *
 * Hex encode data.  The @out string is zero terminated, and @outlen
 * holds the length excluding the terminating zero.  The @out buffer
 * must be deallocated by the caller.
 *
 * Return value: Returns %GSASL_OK on success, or %GSASL_MALLOC_ERROR
 *   if input was too large or memory allocation fail.
 *
 * Since: 1.10
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_hex_to(mut in_0: *const libc::c_char,
                                      mut inlen: size_t,
                                      mut out: *mut *mut libc::c_char,
                                      mut outlen: *mut size_t)
 -> libc::c_int {
    let mut len: size_t =
        inlen.wrapping_mul(2);
    if !outlen.is_null() { *outlen = len }
    *out =
        malloc((*outlen).wrapping_add(1) as u64) as
            *mut libc::c_char;
    if (*out).is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    _gsasl_hex_encode(in_0, inlen, *out);
    *(*out).offset(len as isize) = '\u{0}' as i32 as libc::c_char;
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
/* Utilities: md5pwd.c, base64.c, free.c */
/* *
 * gsasl_hex_from:
 * @in: input byte array
 * @out: pointer to newly allocated output byte array
 * @outlen: pointer to size of newly allocated output byte array
 *
 * Decode hex data.  The @out buffer must be deallocated by the
 * caller.
 *
 * Return value: Returns %GSASL_OK on success, %GSASL_BASE64_ERROR if
 *   input was invalid, and %GSASL_MALLOC_ERROR on memory allocation
 *   errors.
 *
 * Since: 1.10
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_hex_from(mut in_0: *const libc::c_char,
                                        mut out: *mut *mut libc::c_char,
                                        mut outlen: *mut size_t)
 -> libc::c_int {
    let mut inlen: size_t = strlen(in_0) as size_t;
    let mut l: size_t = inlen.wrapping_div(2);
    if inlen.wrapping_rem(2) != 0 {
        return GSASL_BASE64_ERROR as libc::c_int
    }
    if !_gsasl_hex_p(in_0) { return GSASL_BASE64_ERROR as libc::c_int }
    *out = malloc(l as u64) as *mut libc::c_char;
    if (*out).is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    _gsasl_hex_decode(in_0, *out);
    if !outlen.is_null() { *outlen = l }
    return GSASL_OK as libc::c_int;
}
