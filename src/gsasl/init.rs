use ::libc;
use crate::gsasl::consts::{GSASL_CRYPTO_ERROR, GSASL_MALLOC_ERROR, GSASL_OK};
use crate::gsasl::gsasl::{Gsasl, Gsasl_mechanism};

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
