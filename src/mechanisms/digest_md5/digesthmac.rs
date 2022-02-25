use crate::gsasl::gl::free::rpl_free;
use crate::gsasl::gl::gc_gnulib::gc_md5;
use crate::mechanisms::digest_md5::parser::{
    digest_md5_cipher, DIGEST_MD5_CIPHER_RC4_40, DIGEST_MD5_CIPHER_RC4_56,
};
use crate::mechanisms::digest_md5::qop::{
    digest_md5_qop, DIGEST_MD5_QOP_AUTH, DIGEST_MD5_QOP_AUTH_CONF, DIGEST_MD5_QOP_AUTH_INT,
};
use ::libc;
use libc::{malloc, memcpy, size_t, sprintf, strlen};

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
/* digesthmac.h --- Compute DIGEST-MD5 response value.
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
/* Compute in 33 bytes large array OUTPUT the DIGEST-MD5 response
value.  SECRET holds the 16 bytes MD5 hash SS, i.e.,
H(username:realm:passwd).  NONCE is a zero terminated string with
the server nonce.  NC is the nonce-count, typically 1 for initial
authentication.  CNONCE is a zero terminated string with the client
nonce.  QOP is the quality of protection to use.  AUTHZID is a zero
terminated string with the authorization identity.  DIGESTURI is a
zero terminated string with the server principal (e.g.,
imap/mail.example.org).  RSPAUTH is a boolean which indicate
whether to compute a value for the RSPAUTH response or the "real"
authentication.  CIPHER is the cipher to use.  KIC, KIS, KCC, KCS
are either NULL, or points to 16 byte arrays that will hold the
computed keys on output.  Returns 0 on success. */
/* Compute in 33 bytes large array OUTPUT the DIGEST-MD5 response
value.  SECRET holds the 16 bytes MD5 hash SS, i.e.,
H(username:realm:passwd).  NONCE is a zero terminated string with
the server nonce.  NC is the nonce-count, typically 1 for initial
authentication.  CNONCE is a zero terminated string with the client
nonce.  QOP is the quality of protection to use.  AUTHZID is a zero
terminated string with the authorization identity.  DIGESTURI is a
zero terminated string with the server principal (e.g.,
imap/mail.example.org).  RSPAUTH is a boolean which indicate
whether to compute a value for the RSPAUTH response or the "real"
authentication.  CIPHER is the cipher to use.  KIC, KIS, KCC, KCS
are either NULL, or points to 16 byte arrays that will hold the
computed keys on output.  Returns 0 on success. */
#[no_mangle]
pub unsafe fn digest_md5_hmac(
    output: *mut libc::c_char,
    secret: *mut libc::c_char,
    nonce: *const libc::c_char,
    nc: size_t,
    cnonce: *const libc::c_char,
    qop: digest_md5_qop,
    authzid: *const libc::c_char,
    digesturi: *const libc::c_char,
    rspauth: libc::c_int,
    cipher: digest_md5_cipher,
    kic: *mut libc::c_char,
    kis: *mut libc::c_char,
    kcc: *mut libc::c_char,
    kcs: *mut libc::c_char,
) -> libc::c_int {
    let a2string: *const libc::c_char = if rspauth != 0 {
        b":\x00" as *const u8 as *const libc::c_char
    } else {
        b"AUTHENTICATE:\x00" as *const u8 as *const libc::c_char
    }; /* really 9 but 17 for -Werror=format-overflow= */
    let mut nchex: [libc::c_char; 17] = [0; 17];
    let mut a1hexhash: [libc::c_char; 32] = [0; 32];
    let mut a2hexhash: [libc::c_char; 32] = [0; 32];
    let mut hash: [libc::c_char; 16] = [0; 16];
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmplen: size_t = 0;
    let mut rc: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    /* A1 */
    tmplen = 16usize
        .wrapping_add(strlen(b":\x00" as *const u8 as *const libc::c_char))
        .wrapping_add(strlen(nonce))
        .wrapping_add(strlen(b":\x00" as *const u8 as *const libc::c_char))
        .wrapping_add(strlen(cnonce));

    if !authzid.is_null() && strlen(authzid) > 0 {
        tmplen = tmplen.wrapping_add(
            strlen(b":\x00" as *const u8 as *const libc::c_char).wrapping_add(strlen(authzid)),
        )
    }
    tmp = malloc(tmplen) as *mut libc::c_char;
    p = tmp;
    if tmp.is_null() {
        return -(1 as libc::c_int);
    }
    memcpy(p as *mut libc::c_void, secret as *const libc::c_void, 16);

    p = p.offset(16 as libc::c_int as isize);
    memcpy(
        p as *mut libc::c_void,
        b":\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        strlen(b":\x00" as *const u8 as *const libc::c_char),
    );
    p = p.offset(strlen(b":\x00" as *const u8 as *const libc::c_char) as isize);
    memcpy(
        p as *mut libc::c_void,
        nonce as *const libc::c_void,
        strlen(nonce),
    );
    p = p.offset(strlen(nonce) as isize);
    memcpy(
        p as *mut libc::c_void,
        b":\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        strlen(b":\x00" as *const u8 as *const libc::c_char),
    );
    p = p.offset(strlen(b":\x00" as *const u8 as *const libc::c_char) as isize);
    memcpy(
        p as *mut libc::c_void,
        cnonce as *const libc::c_void,
        strlen(cnonce),
    );
    p = p.offset(strlen(cnonce) as isize);
    if !authzid.is_null() && strlen(authzid) > 0 {
        memcpy(
            p as *mut libc::c_void,
            b":\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
            strlen(b":\x00" as *const u8 as *const libc::c_char),
        );
        p = p.offset(strlen(b":\x00" as *const u8 as *const libc::c_char) as isize);
        memcpy(
            p as *mut libc::c_void,
            authzid as *const libc::c_void,
            strlen(authzid),
        );
        p = p.offset(strlen(authzid) as isize)
    }
    rc = gc_md5(
        tmp as *const libc::c_void,
        tmplen,
        hash.as_mut_ptr() as *mut libc::c_void,
    ) as libc::c_int;
    rpl_free(tmp as *mut libc::c_void);
    if rc != 0 {
        return rc;
    }
    if !kic.is_null() {
        let mut hash2: [libc::c_char; 16] = [0; 16];
        let mut q: [libc::c_char; 81] = [0; 81];
        let qlen: size_t = (16 as libc::c_int + 65 as libc::c_int) as size_t;
        memcpy(
            q.as_mut_ptr() as *mut libc::c_void,
            hash.as_mut_ptr() as *const libc::c_void,
            16,
        );
        memcpy(
            q.as_mut_ptr().offset(16 as libc::c_int as isize) as *mut libc::c_void,
            b"Digest session key to client-to-server signing key magic constant\x00" as *const u8
                as *const libc::c_char as *const libc::c_void,
            65,
        );
        rc = gc_md5(
            q.as_mut_ptr() as *const libc::c_void,
            qlen,
            hash2.as_mut_ptr() as *mut libc::c_void,
        ) as libc::c_int;
        if rc != 0 {
            return rc;
        }
        memcpy(
            kic as *mut libc::c_void,
            hash2.as_mut_ptr() as *const libc::c_void,
            16,
        );
    }
    if !kis.is_null() {
        let mut hash2_0: [libc::c_char; 16] = [0; 16];
        let mut q_0: [libc::c_char; 81] = [0; 81];
        let qlen_0: size_t = (16 as libc::c_int + 65 as libc::c_int) as size_t;
        memcpy(
            q_0.as_mut_ptr() as *mut libc::c_void,
            hash.as_mut_ptr() as *const libc::c_void,
            16,
        );
        memcpy(
            q_0.as_mut_ptr().offset(16 as libc::c_int as isize) as *mut libc::c_void,
            b"Digest session key to server-to-client signing key magic constant\x00" as *const u8
                as *const libc::c_char as *const libc::c_void,
            65,
        );
        rc = gc_md5(
            q_0.as_mut_ptr() as *const libc::c_void,
            qlen_0,
            hash2_0.as_mut_ptr() as *mut libc::c_void,
        ) as libc::c_int;
        if rc != 0 {
            return rc;
        }
        memcpy(
            kis as *mut libc::c_void,
            hash2_0.as_mut_ptr() as *const libc::c_void,
            16,
        );
    }
    if !kcc.is_null() {
        let mut hash2_1: [libc::c_char; 16] = [0; 16];
        let mut n: libc::c_int = 0;
        let mut q_1: [libc::c_char; 75] = [0; 75];
        if cipher as libc::c_uint == DIGEST_MD5_CIPHER_RC4_40 as libc::c_int as libc::c_uint {
            n = 5 as libc::c_int
        } else if cipher as libc::c_uint == DIGEST_MD5_CIPHER_RC4_56 as libc::c_int as libc::c_uint
        {
            n = 7 as libc::c_int
        } else {
            n = 16 as libc::c_int
        }
        memcpy(
            q_1.as_mut_ptr() as *mut libc::c_void,
            hash.as_mut_ptr() as *const libc::c_void,
            n as size_t,
        );
        memcpy(
            q_1.as_mut_ptr().offset(n as isize) as *mut libc::c_void,
            b"Digest H(A1) to client-to-server sealing key magic constant\x00" as *const u8
                as *const libc::c_char as *const libc::c_void,
            59,
        );
        rc = gc_md5(
            q_1.as_mut_ptr() as *const libc::c_void,
            (n + 59) as size_t,
            hash2_1.as_mut_ptr() as *mut libc::c_void,
        ) as libc::c_int;
        if rc != 0 {
            return rc;
        }
        memcpy(
            kcc as *mut libc::c_void,
            hash2_1.as_mut_ptr() as *const libc::c_void,
            16,
        );
    }
    if !kcs.is_null() {
        let mut hash2_2: [libc::c_char; 16] = [0; 16];
        let mut n_0: libc::c_int = 0;
        let mut q_2: [libc::c_char; 75] = [0; 75];
        if cipher as libc::c_uint == DIGEST_MD5_CIPHER_RC4_40 as libc::c_int as libc::c_uint {
            n_0 = 5 as libc::c_int
        } else if cipher as libc::c_uint == DIGEST_MD5_CIPHER_RC4_56 as libc::c_int as libc::c_uint
        {
            n_0 = 7 as libc::c_int
        } else {
            n_0 = 16 as libc::c_int
        }
        memcpy(
            q_2.as_mut_ptr() as *mut libc::c_void,
            hash.as_mut_ptr() as *const libc::c_void,
            n_0 as size_t,
        );
        memcpy(
            q_2.as_mut_ptr().offset(n_0 as isize) as *mut libc::c_void,
            b"Digest H(A1) to server-to-client sealing key magic constant\x00" as *const u8
                as *const libc::c_char as *const libc::c_void,
            59,
        );
        rc = gc_md5(
            q_2.as_mut_ptr() as *const libc::c_void,
            (n_0 + 59) as size_t,
            hash2_2.as_mut_ptr() as *mut libc::c_void,
        ) as libc::c_int;
        if rc != 0 {
            return rc;
        }
        memcpy(
            kcs as *mut libc::c_void,
            hash2_2.as_mut_ptr() as *const libc::c_void,
            16,
        );
    }
    i = 0 as libc::c_int;
    while i < 16 as libc::c_int {
        a1hexhash[(2 as libc::c_int * i + 1 as libc::c_int) as usize] =
            if hash[i as usize] as libc::c_int & 0xf as libc::c_int > 9 as libc::c_int {
                ('a' as i32 + (hash[i as usize] as libc::c_int & 0xf as libc::c_int))
                    - 10 as libc::c_int
            } else {
                ('0' as i32) + (hash[i as usize] as libc::c_int & 0xf as libc::c_int)
            } as libc::c_char;
        a1hexhash[(2 as libc::c_int * i + 0 as libc::c_int) as usize] =
            if hash[i as usize] as libc::c_int >> 4 as libc::c_int & 0xf as libc::c_int
                > 9 as libc::c_int
            {
                ('a' as i32
                    + (hash[i as usize] as libc::c_int >> 4 as libc::c_int & 0xf as libc::c_int))
                    - 10 as libc::c_int
            } else {
                ('0' as i32)
                    + (hash[i as usize] as libc::c_int >> 4 as libc::c_int & 0xf as libc::c_int)
            } as libc::c_char;
        i += 1
    }
    /* A2 */
    tmplen = strlen(a2string).wrapping_add(strlen(digesturi));
    if qop as libc::c_uint & DIGEST_MD5_QOP_AUTH_INT as libc::c_int as libc::c_uint != 0
        || qop as libc::c_uint & DIGEST_MD5_QOP_AUTH_CONF as libc::c_int as libc::c_uint != 0
    {
        tmplen = tmplen.wrapping_add(strlen(
            b":00000000000000000000000000000000\x00" as *const u8 as *const libc::c_char,
        ))
    }
    tmp = malloc(tmplen) as *mut libc::c_char;
    p = tmp;
    if tmp.is_null() {
        return -(1 as libc::c_int);
    }
    memcpy(
        p as *mut libc::c_void,
        a2string as *const libc::c_void,
        strlen(a2string),
    );
    p = p.offset(strlen(a2string) as isize);
    memcpy(
        p as *mut libc::c_void,
        digesturi as *const libc::c_void,
        strlen(digesturi),
    );
    p = p.offset(strlen(digesturi) as isize);
    if qop as libc::c_uint & DIGEST_MD5_QOP_AUTH_INT as libc::c_int as libc::c_uint != 0
        || qop as libc::c_uint & DIGEST_MD5_QOP_AUTH_CONF as libc::c_int as libc::c_uint != 0
    {
        memcpy(
            p as *mut libc::c_void,
            b":00000000000000000000000000000000\x00" as *const u8 as *const libc::c_char
                as *const libc::c_void,
            strlen(b":00000000000000000000000000000000\x00" as *const u8 as *const libc::c_char),
        );
    }
    rc = gc_md5(
        tmp as *const libc::c_void,
        tmplen,
        hash.as_mut_ptr() as *mut libc::c_void,
    ) as libc::c_int;
    rpl_free(tmp as *mut libc::c_void);
    if rc != 0 {
        return rc;
    }
    i = 0 as libc::c_int;
    while i < 16 as libc::c_int {
        a2hexhash[(2 as libc::c_int * i + 1 as libc::c_int) as usize] =
            if hash[i as usize] as libc::c_int & 0xf as libc::c_int > 9 as libc::c_int {
                ('a' as i32 + (hash[i as usize] as libc::c_int & 0xf as libc::c_int))
                    - 10 as libc::c_int
            } else {
                ('0' as i32) + (hash[i as usize] as libc::c_int & 0xf as libc::c_int)
            } as libc::c_char;
        a2hexhash[(2 as libc::c_int * i + 0 as libc::c_int) as usize] =
            if hash[i as usize] as libc::c_int >> 4 as libc::c_int & 0xf as libc::c_int
                > 9 as libc::c_int
            {
                ('a' as i32
                    + (hash[i as usize] as libc::c_int >> 4 as libc::c_int & 0xf as libc::c_int))
                    - 10 as libc::c_int
            } else {
                ('0' as i32)
                    + (hash[i as usize] as libc::c_int >> 4 as libc::c_int & 0xf as libc::c_int)
            } as libc::c_char;
        i += 1
    }
    /* response_value */
    sprintf(
        nchex.as_mut_ptr(),
        b"%08lx\x00" as *const u8 as *const libc::c_char,
        nc,
    );
    tmplen = (2usize * 16)
        .wrapping_add(strlen(b":\x00" as *const u8 as *const libc::c_char))
        .wrapping_add(strlen(nonce))
        .wrapping_add(strlen(b":\x00" as *const u8 as *const libc::c_char))
        .wrapping_add(strlen(nchex.as_mut_ptr()))
        .wrapping_add(strlen(b":\x00" as *const u8 as *const libc::c_char))
        .wrapping_add(strlen(cnonce))
        .wrapping_add(strlen(b":\x00" as *const u8 as *const libc::c_char));
    if qop as libc::c_uint & DIGEST_MD5_QOP_AUTH_CONF != 0 {
        tmplen = tmplen.wrapping_add(strlen(b"auth-conf\x00" as *const u8 as *const libc::c_char))
    } else if qop as libc::c_uint & DIGEST_MD5_QOP_AUTH_INT as libc::c_int as libc::c_uint != 0 {
        tmplen = tmplen.wrapping_add(strlen(b"auth-int\x00" as *const u8 as *const libc::c_char))
    } else if qop as libc::c_uint & DIGEST_MD5_QOP_AUTH != 0 {
        tmplen = tmplen.wrapping_add(strlen(b"auth\x00" as *const u8 as *const libc::c_char))
    }
    tmplen = tmplen
        .wrapping_add(strlen(b":\x00" as *const u8 as *const libc::c_char).wrapping_add(2 * 16));
    tmp = malloc(tmplen) as *mut libc::c_char;

    p = tmp;
    if tmp.is_null() {
        return -(1 as libc::c_int);
    }
    memcpy(
        p as *mut libc::c_void,
        a1hexhash.as_mut_ptr() as *const libc::c_void,
        2 * 16,
    );
    p = p.offset((2 * 16) as isize);
    memcpy(
        p as *mut libc::c_void,
        b":\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        strlen(b":\x00" as *const u8 as *const libc::c_char),
    );
    p = p.offset(strlen(b":\x00" as *const u8 as *const libc::c_char) as isize);
    memcpy(
        p as *mut libc::c_void,
        nonce as *const libc::c_void,
        strlen(nonce),
    );
    p = p.offset(strlen(nonce) as isize);
    memcpy(
        p as *mut libc::c_void,
        b":\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        strlen(b":\x00" as *const u8 as *const libc::c_char),
    );
    p = p.offset(strlen(b":\x00" as *const u8 as *const libc::c_char) as isize);
    memcpy(
        p as *mut libc::c_void,
        nchex.as_mut_ptr() as *const libc::c_void,
        strlen(nchex.as_mut_ptr()),
    );
    p = p.offset(strlen(nchex.as_mut_ptr()) as isize);
    memcpy(
        p as *mut libc::c_void,
        b":\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        strlen(b":\x00" as *const u8 as *const libc::c_char),
    );
    p = p.offset(strlen(b":\x00" as *const u8 as *const libc::c_char) as isize);
    memcpy(
        p as *mut libc::c_void,
        cnonce as *const libc::c_void,
        strlen(cnonce),
    );
    p = p.offset(strlen(cnonce) as isize);
    memcpy(
        p as *mut libc::c_void,
        b":\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        strlen(b":\x00" as *const u8 as *const libc::c_char),
    );
    p = p.offset(strlen(b":\x00" as *const u8 as *const libc::c_char) as isize);
    if qop as libc::c_uint & DIGEST_MD5_QOP_AUTH_CONF as libc::c_int as libc::c_uint != 0 {
        memcpy(
            p as *mut libc::c_void,
            b"auth-conf\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
            strlen(b"auth-conf\x00" as *const u8 as *const libc::c_char),
        );
        p = p.offset(strlen(b"auth-conf\x00" as *const u8 as *const libc::c_char) as isize)
    } else if qop as libc::c_uint & DIGEST_MD5_QOP_AUTH_INT != 0 {
        memcpy(
            p as *mut libc::c_void,
            b"auth-int\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
            strlen(b"auth-int\x00" as *const u8 as *const libc::c_char),
        );
        p = p.offset(strlen(b"auth-int\x00" as *const u8 as *const libc::c_char) as isize)
    } else if qop as libc::c_uint & DIGEST_MD5_QOP_AUTH as libc::c_int as libc::c_uint != 0 {
        memcpy(
            p as *mut libc::c_void,
            b"auth\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
            strlen(b"auth\x00" as *const u8 as *const libc::c_char),
        );
        p = p.offset(strlen(b"auth\x00" as *const u8 as *const libc::c_char) as isize)
    }
    memcpy(
        p as *mut libc::c_void,
        b":\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        strlen(b":\x00" as *const u8 as *const libc::c_char),
    );
    p = p.offset(strlen(b":\x00" as *const u8 as *const libc::c_char) as isize);
    memcpy(
        p as *mut libc::c_void,
        a2hexhash.as_mut_ptr() as *const libc::c_void,
        2 * 16,
    );
    rc = gc_md5(
        tmp as *const libc::c_void,
        tmplen,
        hash.as_mut_ptr() as *mut libc::c_void,
    ) as libc::c_int;
    rpl_free(tmp as *mut libc::c_void);
    if rc != 0 {
        return rc;
    }
    i = 0 as libc::c_int;
    while i < 16 as libc::c_int {
        *output.offset((2 as libc::c_int * i + 1 as libc::c_int) as isize) =
            if hash[i as usize] as libc::c_int & 0xf as libc::c_int > 9 as libc::c_int {
                ('a' as i32 + (hash[i as usize] as libc::c_int & 0xf as libc::c_int))
                    - 10 as libc::c_int
            } else {
                ('0' as i32) + (hash[i as usize] as libc::c_int & 0xf as libc::c_int)
            } as libc::c_char;
        *output.offset((2 as libc::c_int * i + 0 as libc::c_int) as isize) =
            if hash[i as usize] as libc::c_int >> 4 as libc::c_int & 0xf as libc::c_int
                > 9 as libc::c_int
            {
                ('a' as i32
                    + (hash[i as usize] as libc::c_int >> 4 as libc::c_int & 0xf as libc::c_int))
                    - 10 as libc::c_int
            } else {
                ('0' as i32)
                    + (hash[i as usize] as libc::c_int >> 4 as libc::c_int & 0xf as libc::c_int)
            } as libc::c_char;
        i += 1
    }
    *output.offset(32 as libc::c_int as isize) = '\u{0}' as i32 as libc::c_char;
    return 0 as libc::c_int;
}
