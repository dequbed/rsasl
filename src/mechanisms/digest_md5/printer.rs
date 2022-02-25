use crate::gsasl::gl::free::rpl_free;
use crate::mechanisms::digest_md5::parser::{
    digest_md5_challenge, digest_md5_finish, digest_md5_response, DIGEST_MD5_CIPHER_3DES,
    DIGEST_MD5_CIPHER_AES_CBC, DIGEST_MD5_CIPHER_DES, DIGEST_MD5_CIPHER_RC4,
    DIGEST_MD5_CIPHER_RC4_40, DIGEST_MD5_CIPHER_RC4_56,
};
use crate::mechanisms::digest_md5::qop::{
    DIGEST_MD5_QOP_AUTH, DIGEST_MD5_QOP_AUTH_CONF, DIGEST_MD5_QOP_AUTH_INT,
};
use crate::mechanisms::digest_md5::validate::{
    digest_md5_validate_challenge, digest_md5_validate_finish, digest_md5_validate_response,
};
use ::libc;
use libc::size_t;

extern "C" {
    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char, _: ...) -> libc::c_int;
}

/* printer.h --- Convert DIGEST-MD5 token structures into strings.
 * Copyright (C) 2004-2021 Simon Josefsson
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
/* Get prototypes. */
/* Get free. */
/* Get asprintf. */
/* Get token validator. */
/* Append a key/value pair to a comma'd string list.  Additionally enclose
the value in quotes if requested. */
unsafe fn comma_append(
    dst: *mut *mut libc::c_char,
    key: *const libc::c_char,
    value: *const libc::c_char,
    quotes: libc::c_int,
) -> libc::c_int {
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let result: libc::c_int;
    if !(*dst).is_null() {
        if !value.is_null() {
            if quotes != 0 {
                result = asprintf(
                    &mut tmp as *mut *mut libc::c_char,
                    b"%s, %s=\"%s\"\x00" as *const u8 as *const libc::c_char,
                    *dst,
                    key,
                    value,
                )
            } else {
                result = asprintf(
                    &mut tmp as *mut *mut libc::c_char,
                    b"%s, %s=%s\x00" as *const u8 as *const libc::c_char,
                    *dst,
                    key,
                    value,
                )
            }
        } else {
            result = asprintf(
                &mut tmp as *mut *mut libc::c_char,
                b"%s, %s\x00" as *const u8 as *const libc::c_char,
                *dst,
                key,
            )
        }
    } else if !value.is_null() {
        if quotes != 0 {
            result = asprintf(
                &mut tmp as *mut *mut libc::c_char,
                b"%s=\"%s\"\x00" as *const u8 as *const libc::c_char,
                key,
                value,
            )
        } else {
            result = asprintf(
                &mut tmp as *mut *mut libc::c_char,
                b"%s=%s\x00" as *const u8 as *const libc::c_char,
                key,
                value,
            )
        }
    } else {
        result = asprintf(
            &mut tmp as *mut *mut libc::c_char,
            b"%s\x00" as *const u8 as *const libc::c_char,
            key,
        )
    }
    if result < 0 as libc::c_int {
        return result;
    }
    rpl_free(*dst as *mut libc::c_void);
    *dst = tmp;
    return result;
}
/* printer.h --- Convert DIGEST-MD5 token structures into strings.
 * Copyright (C) 2004-2021 Simon Josefsson
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
/* Get token types. */
#[no_mangle]
pub unsafe fn digest_md5_print_challenge(c: *mut digest_md5_challenge) -> *mut libc::c_char {
    let mut out: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: size_t;
    /* Below we assume the mandatory fields are present, verify that
    first to avoid crashes. */
    if digest_md5_validate_challenge(c) != 0 as libc::c_int {
        return 0 as *mut libc::c_char;
    }
    i = 0 as libc::c_int as size_t;
    while i < (*c).nrealms {
        if comma_append(
            &mut out,
            b"realm\x00" as *const u8 as *const libc::c_char,
            *(*c).realms.offset(i as isize),
            1 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
        i = i.wrapping_add(1)
    }
    if !(*c).nonce.is_null() {
        if comma_append(
            &mut out,
            b"nonce\x00" as *const u8 as *const libc::c_char,
            (*c).nonce,
            1 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
    }
    if (*c).qops != 0 {
        let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
        if (*c).qops & DIGEST_MD5_QOP_AUTH as libc::c_int != 0 {
            if comma_append(
                &mut tmp,
                b"auth\x00" as *const u8 as *const libc::c_char,
                0 as *const libc::c_char,
                0 as libc::c_int,
            ) < 0 as libc::c_int
            {
                rpl_free(tmp as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char;
            }
        }
        if (*c).qops & DIGEST_MD5_QOP_AUTH_INT as libc::c_int != 0 {
            if comma_append(
                &mut tmp,
                b"auth-int\x00" as *const u8 as *const libc::c_char,
                0 as *const libc::c_char,
                0 as libc::c_int,
            ) < 0 as libc::c_int
            {
                rpl_free(tmp as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char;
            }
        }
        if (*c).qops & DIGEST_MD5_QOP_AUTH_CONF as libc::c_int != 0 {
            if comma_append(
                &mut tmp,
                b"auth-conf\x00" as *const u8 as *const libc::c_char,
                0 as *const libc::c_char,
                0 as libc::c_int,
            ) < 0 as libc::c_int
            {
                rpl_free(tmp as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char;
            }
        }
        if comma_append(
            &mut out,
            b"qop\x00" as *const u8 as *const libc::c_char,
            tmp,
            1 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(tmp as *mut libc::c_void);
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
        rpl_free(tmp as *mut libc::c_void);
    }
    if (*c).stale != 0 {
        if comma_append(
            &mut out,
            b"stale\x00" as *const u8 as *const libc::c_char,
            b"true\x00" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
    }
    if (*c).servermaxbuf != 0 {
        let mut tmp_0: *mut libc::c_char = 0 as *mut libc::c_char;
        if asprintf(
            &mut tmp_0 as *mut *mut libc::c_char,
            b"%lu\x00" as *const u8 as *const libc::c_char,
            (*c).servermaxbuf,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
        if comma_append(
            &mut out,
            b"maxbuf\x00" as *const u8 as *const libc::c_char,
            tmp_0,
            0 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
        rpl_free(tmp_0 as *mut libc::c_void);
    }
    if (*c).utf8 != 0 {
        if comma_append(
            &mut out,
            b"charset\x00" as *const u8 as *const libc::c_char,
            b"utf-8\x00" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
    }
    if comma_append(
        &mut out,
        b"algorithm\x00" as *const u8 as *const libc::c_char,
        b"md5-sess\x00" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    ) < 0 as libc::c_int
    {
        rpl_free(out as *mut libc::c_void);
        return 0 as *mut libc::c_char;
    }
    if (*c).ciphers != 0 {
        let mut tmp_1: *mut libc::c_char = 0 as *mut libc::c_char;
        if (*c).ciphers & DIGEST_MD5_CIPHER_3DES as libc::c_int != 0 {
            if comma_append(
                &mut tmp_1,
                b"3des\x00" as *const u8 as *const libc::c_char,
                0 as *const libc::c_char,
                0 as libc::c_int,
            ) < 0 as libc::c_int
            {
                rpl_free(tmp_1 as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char;
            }
        }
        if (*c).ciphers & DIGEST_MD5_CIPHER_DES as libc::c_int != 0 {
            if comma_append(
                &mut tmp_1,
                b"des\x00" as *const u8 as *const libc::c_char,
                0 as *const libc::c_char,
                0 as libc::c_int,
            ) < 0 as libc::c_int
            {
                rpl_free(tmp_1 as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char;
            }
        }
        if (*c).ciphers & DIGEST_MD5_CIPHER_RC4_40 as libc::c_int != 0 {
            if comma_append(
                &mut tmp_1,
                b"rc4-40\x00" as *const u8 as *const libc::c_char,
                0 as *const libc::c_char,
                0 as libc::c_int,
            ) < 0 as libc::c_int
            {
                rpl_free(tmp_1 as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char;
            }
        }
        if (*c).ciphers & DIGEST_MD5_CIPHER_RC4 as libc::c_int != 0 {
            if comma_append(
                &mut tmp_1,
                b"rc4\x00" as *const u8 as *const libc::c_char,
                0 as *const libc::c_char,
                0 as libc::c_int,
            ) < 0 as libc::c_int
            {
                rpl_free(tmp_1 as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char;
            }
        }
        if (*c).ciphers & DIGEST_MD5_CIPHER_RC4_56 as libc::c_int != 0 {
            if comma_append(
                &mut tmp_1,
                b"rc4-56\x00" as *const u8 as *const libc::c_char,
                0 as *const libc::c_char,
                0 as libc::c_int,
            ) < 0 as libc::c_int
            {
                rpl_free(tmp_1 as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char;
            }
        }
        if (*c).ciphers & DIGEST_MD5_CIPHER_AES_CBC as libc::c_int != 0 {
            if comma_append(
                &mut tmp_1,
                b"aes-cbc\x00" as *const u8 as *const libc::c_char,
                0 as *const libc::c_char,
                0 as libc::c_int,
            ) < 0 as libc::c_int
            {
                rpl_free(tmp_1 as *mut libc::c_void);
                rpl_free(out as *mut libc::c_void);
                return 0 as *mut libc::c_char;
            }
        }
        if comma_append(
            &mut out,
            b"cipher\x00" as *const u8 as *const libc::c_char,
            tmp_1,
            1 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(tmp_1 as *mut libc::c_void);
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
        rpl_free(tmp_1 as *mut libc::c_void);
    }
    return out;
}
#[no_mangle]
pub unsafe fn digest_md5_print_response(r: *mut digest_md5_response) -> *mut libc::c_char {
    let mut out: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut qop: *const libc::c_char = 0 as *const libc::c_char;
    let mut cipher: *const libc::c_char = 0 as *const libc::c_char;
    /* Below we assume the mandatory fields are present, verify that
    first to avoid crashes. */
    if digest_md5_validate_response(r) != 0 as libc::c_int {
        return 0 as *mut libc::c_char;
    }
    if (*r).qop as libc::c_uint & DIGEST_MD5_QOP_AUTH_CONF as libc::c_int as libc::c_uint != 0 {
        qop = b"qop=auth-conf\x00" as *const u8 as *const libc::c_char
    } else if (*r).qop as libc::c_uint & DIGEST_MD5_QOP_AUTH_INT as libc::c_int as libc::c_uint != 0
    {
        qop = b"qop=auth-int\x00" as *const u8 as *const libc::c_char
    } else if (*r).qop as libc::c_uint & DIGEST_MD5_QOP_AUTH as libc::c_int as libc::c_uint != 0 {
        qop = b"qop=auth\x00" as *const u8 as *const libc::c_char
    }
    if (*r).cipher as libc::c_uint & DIGEST_MD5_CIPHER_3DES as libc::c_int as libc::c_uint != 0 {
        cipher = b"cipher=3des\x00" as *const u8 as *const libc::c_char
    } else if (*r).cipher as libc::c_uint & DIGEST_MD5_CIPHER_DES as libc::c_int as libc::c_uint
        != 0
    {
        cipher = b"cipher=des\x00" as *const u8 as *const libc::c_char
    } else if (*r).cipher as libc::c_uint & DIGEST_MD5_CIPHER_RC4_40 as libc::c_int as libc::c_uint
        != 0
    {
        cipher = b"cipher=rc4-40\x00" as *const u8 as *const libc::c_char
    } else if (*r).cipher as libc::c_uint & DIGEST_MD5_CIPHER_RC4 as libc::c_int as libc::c_uint
        != 0
    {
        cipher = b"cipher=rc4\x00" as *const u8 as *const libc::c_char
    } else if (*r).cipher as libc::c_uint & DIGEST_MD5_CIPHER_RC4_56 as libc::c_int as libc::c_uint
        != 0
    {
        cipher = b"cipher=rc4-56\x00" as *const u8 as *const libc::c_char
    } else if (*r).cipher as libc::c_uint & DIGEST_MD5_CIPHER_AES_CBC as libc::c_int as libc::c_uint
        != 0
    {
        cipher = b"cipher=aes-cbc\x00" as *const u8 as *const libc::c_char
    }
    if !(*r).username.is_null() {
        if comma_append(
            &mut out,
            b"username\x00" as *const u8 as *const libc::c_char,
            (*r).username,
            1 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
    }
    if !(*r).realm.is_null() {
        if comma_append(
            &mut out,
            b"realm\x00" as *const u8 as *const libc::c_char,
            (*r).realm,
            1 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
    }
    if !(*r).nonce.is_null() {
        if comma_append(
            &mut out,
            b"nonce\x00" as *const u8 as *const libc::c_char,
            (*r).nonce,
            1 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
    }
    if !(*r).cnonce.is_null() {
        if comma_append(
            &mut out,
            b"cnonce\x00" as *const u8 as *const libc::c_char,
            (*r).cnonce,
            1 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
    }
    if (*r).nc != 0 {
        let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
        if asprintf(
            &mut tmp as *mut *mut libc::c_char,
            b"%08lx\x00" as *const u8 as *const libc::c_char,
            (*r).nc,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
        if comma_append(
            &mut out,
            b"nc\x00" as *const u8 as *const libc::c_char,
            tmp,
            0 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(tmp as *mut libc::c_void);
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
        rpl_free(tmp as *mut libc::c_void);
    }
    if !qop.is_null() {
        if comma_append(&mut out, qop, 0 as *const libc::c_char, 0 as libc::c_int)
            < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
    }
    if !(*r).digesturi.is_null() {
        if comma_append(
            &mut out,
            b"digest-uri\x00" as *const u8 as *const libc::c_char,
            (*r).digesturi,
            1 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
    }
    if !(*r).response.as_mut_ptr().is_null() {
        if comma_append(
            &mut out,
            b"response\x00" as *const u8 as *const libc::c_char,
            (*r).response.as_mut_ptr(),
            0 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
    }
    if (*r).clientmaxbuf != 0 {
        let mut tmp_0: *mut libc::c_char = 0 as *mut libc::c_char;
        if asprintf(
            &mut tmp_0 as *mut *mut libc::c_char,
            b"%lu\x00" as *const u8 as *const libc::c_char,
            (*r).clientmaxbuf,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
        if comma_append(
            &mut out,
            b"maxbuf\x00" as *const u8 as *const libc::c_char,
            tmp_0,
            0 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(tmp_0 as *mut libc::c_void);
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
        rpl_free(tmp_0 as *mut libc::c_void);
    }
    if (*r).utf8 != 0 {
        if comma_append(
            &mut out,
            b"charset\x00" as *const u8 as *const libc::c_char,
            b"utf-8\x00" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
    }
    if !cipher.is_null() {
        if comma_append(&mut out, cipher, 0 as *const libc::c_char, 0 as libc::c_int)
            < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
    }
    if !(*r).authzid.is_null() {
        if comma_append(
            &mut out,
            b"authzid\x00" as *const u8 as *const libc::c_char,
            (*r).authzid,
            1 as libc::c_int,
        ) < 0 as libc::c_int
        {
            rpl_free(out as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
    }
    return out;
}
#[no_mangle]
pub unsafe fn digest_md5_print_finish(finish: *mut digest_md5_finish) -> *mut libc::c_char {
    let mut out: *mut libc::c_char = 0 as *mut libc::c_char;
    /* Below we assume the mandatory fields are present, verify that
    first to avoid crashes. */
    if digest_md5_validate_finish(finish) != 0 as libc::c_int {
        return 0 as *mut libc::c_char;
    }
    if asprintf(
        &mut out as *mut *mut libc::c_char,
        b"rspauth=%s\x00" as *const u8 as *const libc::c_char,
        (*finish).rspauth.as_mut_ptr(),
    ) < 0 as libc::c_int
    {
        return 0 as *mut libc::c_char;
    }
    return out;
}
