use ::libc;
extern "C" {
    #[no_mangle]
    fn gsasl_done(ctx: *mut Gsasl);
    /* Register new mechanism: register.c. */
    #[no_mangle]
    fn gsasl_register(ctx: *mut Gsasl, mech: *const Gsasl_mechanism)
     -> libc::c_int;
    #[no_mangle]
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    /* Call before respectively after any other functions. */
    #[no_mangle]
    fn gc_init() -> Gc_rc;
    /* cram-md5.h --- Prototypes for CRAM-MD5 mechanism as defined in RFC 2195.
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
    static mut gsasl_cram_md5_mechanism: Gsasl_mechanism;
    /* external.h --- Prototypes for EXTERNAL mechanism as defined in RFC 2222.
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
    static mut gsasl_external_mechanism: Gsasl_mechanism;
    /* anonymous.h --- Prototypes for ANONYMOUS mechanism as defined in RFC 2245.
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
    static mut gsasl_anonymous_mechanism: Gsasl_mechanism;
    /* plain.h --- Prototypes for SASL mechanism PLAIN as defined in RFC 2595.
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
    static mut gsasl_plain_mechanism: Gsasl_mechanism;
    /* securid.h --- Prototypes for SASL mechanism SECURID as defined in RFC 2808.
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
    static mut gsasl_securid_mechanism: Gsasl_mechanism;
    /* digest-md5.h --- Prototypes for DIGEST-MD5 mechanism as defined in RFC 2831.
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
    static mut gsasl_digest_md5_mechanism: Gsasl_mechanism;
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
    #[no_mangle]
    static mut gsasl_scram_sha1_mechanism: Gsasl_mechanism;
    #[no_mangle]
    static mut gsasl_scram_sha1_plus_mechanism: Gsasl_mechanism;
    #[no_mangle]
    static mut gsasl_scram_sha256_mechanism: Gsasl_mechanism;
    #[no_mangle]
    static mut gsasl_scram_sha256_plus_mechanism: Gsasl_mechanism;
    /* saml20.h --- Prototypes for SAML20.
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
    #[no_mangle]
    static mut gsasl_saml20_mechanism: Gsasl_mechanism;
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
    static mut gsasl_openid20_mechanism: Gsasl_mechanism;
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
    static mut gsasl_login_mechanism: Gsasl_mechanism;
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
pub const GC_OK: Gc_rc = 0;
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
/* Get size_t. */
pub type Gc_rc = libc::c_uint;
pub const GC_PKCS5_DERIVED_KEY_TOO_LONG: Gc_rc = 8;
pub const GC_PKCS5_INVALID_DERIVED_KEY_LENGTH: Gc_rc = 7;
pub const GC_PKCS5_INVALID_ITERATION_COUNT: Gc_rc = 6;
pub const GC_INVALID_HASH: Gc_rc = 5;
pub const GC_INVALID_CIPHER: Gc_rc = 4;
pub const GC_RANDOM_ERROR: Gc_rc = 3;
pub const GC_INIT_ERROR: Gc_rc = 2;
pub const GC_MALLOC_ERROR: Gc_rc = 1;
/* init.c --- Entry point for libgsasl.
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
/* Get gc_init. */
/* Get mechanism headers. */
/* *
 * GSASL_VALID_MECHANISM_CHARACTERS:
 *
 * A zero-terminated character array, or string, with all ASCII
 * characters that may be used within a SASL mechanism name.
 **/
#[no_mangle]
pub static mut GSASL_VALID_MECHANISM_CHARACTERS: *const libc::c_char =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_\x00" as *const u8 as
        *const libc::c_char;
unsafe extern "C" fn register_builtin_mechs(mut ctx: *mut Gsasl)
 -> libc::c_int {
    let mut rc: libc::c_int = GSASL_OK as libc::c_int;
    rc = gsasl_register(ctx, &mut gsasl_anonymous_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_ANONYMOUS */
    rc = gsasl_register(ctx, &mut gsasl_external_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_EXTERNAL */
    rc = gsasl_register(ctx, &mut gsasl_login_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_LOGIN */
    rc = gsasl_register(ctx, &mut gsasl_plain_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_PLAIN */
    rc = gsasl_register(ctx, &mut gsasl_securid_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_SECURID */
    /* USE_NTLM */
    rc = gsasl_register(ctx, &mut gsasl_digest_md5_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_DIGEST_MD5 */
    rc = gsasl_register(ctx, &mut gsasl_cram_md5_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_CRAM_MD5 */
    rc = gsasl_register(ctx, &mut gsasl_scram_sha1_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    rc = gsasl_register(ctx, &mut gsasl_scram_sha1_plus_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_SCRAM_SHA1 */
    rc = gsasl_register(ctx, &mut gsasl_scram_sha256_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    rc = gsasl_register(ctx, &mut gsasl_scram_sha256_plus_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_SCRAM_SHA256 */
    rc = gsasl_register(ctx, &mut gsasl_saml20_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_SAML20 */
    rc = gsasl_register(ctx, &mut gsasl_openid20_mechanism);
    if rc != GSASL_OK as libc::c_int { return rc }
    /* USE_OPENID20 */
    /* USE_GSSAPI */
    /* USE_GSSAPI */
    return GSASL_OK as libc::c_int;
}
/* *
 * gsasl_init:
 * @ctx: pointer to libgsasl handle.
 *
 * This functions initializes libgsasl.  The handle pointed to by ctx
 * is valid for use with other libgsasl functions iff this function is
 * successful.  It also register all builtin SASL mechanisms, using
 * gsasl_register().
 *
 * Return value: GSASL_OK iff successful, otherwise
 * %GSASL_MALLOC_ERROR.
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_init(mut ctx: *mut *mut Gsasl) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    if gc_init() as libc::c_uint != GC_OK as libc::c_int as libc::c_uint {
        return GSASL_CRYPTO_ERROR as libc::c_int
    }
    *ctx =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<Gsasl>() as libc::c_ulong) as *mut Gsasl;
    if (*ctx).is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    rc = register_builtin_mechs(*ctx);
    if rc != GSASL_OK as libc::c_int { gsasl_done(*ctx); return rc }
    return GSASL_OK as libc::c_int;
}
