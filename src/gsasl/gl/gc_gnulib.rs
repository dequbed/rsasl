use ::libc;
use digest::{Digest, Mac};
use digest::generic_array::GenericArray;
use libc::{__errno_location, getrandom, size_t, ssize_t};
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;

use crate::gsasl::gc::{Gc_rc, GC_INVALID_HASH, GC_OK, GC_RANDOM_ERROR};

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
/* Hash types. */
pub type Gc_hash = libc::c_uint;
pub const GC_SM3: Gc_hash = 9;
pub const GC_SHA224: Gc_hash = 8;
pub const GC_SHA512: Gc_hash = 7;
pub const GC_SHA384: Gc_hash = 6;
pub const GC_SHA256: Gc_hash = 5;
pub const GC_RMD160: Gc_hash = 4;
pub const GC_MD2: Gc_hash = 3;
pub const GC_SHA1: Gc_hash = 2;
pub const GC_MD5: Gc_hash = 1;
pub const GC_MD4: Gc_hash = 0;
pub type Gc_hash_mode = libc::c_uint;
pub const GC_HMAC: Gc_hash_mode = 1;
pub const GC_NULL: Gc_hash_mode = 0;
pub type gc_hash_handle = *mut libc::c_void;
/* Cipher types. */
pub type Gc_cipher = libc::c_uint;
pub const GC_CAMELLIA256: Gc_cipher = 9;
pub const GC_CAMELLIA128: Gc_cipher = 8;
pub const GC_ARCTWO40: Gc_cipher = 7;
pub const GC_ARCFOUR40: Gc_cipher = 6;
pub const GC_ARCFOUR128: Gc_cipher = 5;
pub const GC_DES: Gc_cipher = 4;
pub const GC_3DES: Gc_cipher = 3;
pub const GC_AES256: Gc_cipher = 2;
pub const GC_AES192: Gc_cipher = 1;
pub const GC_AES128: Gc_cipher = 0;
pub type Gc_cipher_mode = libc::c_uint;
pub const GC_STREAM: Gc_cipher_mode = 2;
pub const GC_CBC: Gc_cipher_mode = 1;
pub const GC_ECB: Gc_cipher_mode = 0;
pub type gc_cipher_handle = *mut libc::c_void;
/* Memory allocation (avoid). */
pub type gc_malloc_t = Option<unsafe fn(_: size_t) -> *mut libc::c_void>;
pub type gc_secure_check_t = Option<unsafe fn(_: *const libc::c_void) -> libc::c_int>;
pub type gc_realloc_t = Option<unsafe fn(_: *mut libc::c_void, _: size_t) -> *mut libc::c_void>;
pub type gc_free_t = Option<unsafe fn(_: *mut libc::c_void) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _gc_cipher_ctx {
    pub alg: Gc_cipher,
    pub mode: Gc_cipher_mode,
}

/* Call before respectively after any other functions. */
/* gc-gnulib.c --- Common gnulib internal crypto interface functions
 * Copyright (C) 2002-2021 Free Software Foundation, Inc.
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

/* Overwrite BUFFER with random data, under the control of getrandom
FLAGS.  BUFFER contains LENGTH bytes.  Inspired by getentropy,
however LENGTH is not restricted to 256.  Return 0 on success, -1
(setting errno) on failure.  */
unsafe fn randomize(
    mut buffer: *mut libc::c_void,
    mut length: size_t,
    mut flags: libc::c_uint,
) -> libc::c_int {
    let mut buf: *mut libc::c_char = buffer as *mut libc::c_char;
    loop {
        let mut bytes: ssize_t = 0;
        if length == 0 {
            return GC_OK as libc::c_int;
        }
        loop {
            bytes = getrandom(buf as *mut libc::c_void, length, flags);
            if !(bytes < 0) {
                break;
            }
            if *__errno_location() != 4 as libc::c_int {
                return GC_RANDOM_ERROR as libc::c_int;
            }
        }
        if bytes == 0 {
            break;
        }
        buf = buf.offset(bytes as isize);
        length = (length as libc::c_ulong).wrapping_sub(bytes as libc::c_ulong) as size_t as size_t
    }
    return GC_RANDOM_ERROR as libc::c_int;
}
/* Randomness. */
pub unsafe fn gc_nonce(mut data: *mut libc::c_char, mut datalen: size_t) -> Gc_rc {
    return randomize(
        data as *mut libc::c_void,
        datalen,
        0 as libc::c_int as libc::c_uint,
    ) as Gc_rc;
}

pub unsafe fn gc_random(mut data: *mut libc::c_char, mut datalen: size_t) -> Gc_rc {
    return randomize(
        data as *mut libc::c_void,
        datalen,
        0x2 as libc::c_int as libc::c_uint,
    ) as Gc_rc;
}

pub unsafe fn gc_md5(
    mut in_0: *const libc::c_void,
    mut inlen: size_t,
    mut resbuf: *mut libc::c_void,
) -> Gc_rc {
    let mut hasher = md5::Md5::default();
    let input = std::slice::from_raw_parts(in_0 as *const u8, inlen);
    hasher.update(input);
    let output = std::slice::from_raw_parts_mut(resbuf as *mut u8, Md5::output_size());
    let output = GenericArray::from_mut_slice(output);
    hasher.finalize_into(output);
    return GC_OK;
}

pub unsafe fn gc_sha1(
    mut in_0: *const libc::c_void,
    mut inlen: size_t,
    mut resbuf: *mut libc::c_void,
) -> Gc_rc {
    let mut hasher = sha1::Sha1::default();
    let input = std::slice::from_raw_parts(in_0 as *const u8, inlen);
    hasher.update(input);
    let output = std::slice::from_raw_parts_mut(resbuf as *mut u8, Sha1::output_size());
    let output = GenericArray::from_mut_slice(output);
    hasher.finalize_into(output);
    return GC_OK;
}

pub unsafe fn gc_sha256(
    mut in_0: *const libc::c_void,
    mut inlen: size_t,
    mut resbuf: *mut libc::c_void,
) -> Gc_rc {
    let mut hasher = sha2::Sha256::default();
    let input = std::slice::from_raw_parts(in_0 as *const u8, inlen);
    hasher.update(input);
    let output = std::slice::from_raw_parts_mut(resbuf as *mut u8, Sha256::output_size());
    let output = GenericArray::from_mut_slice(output);
    hasher.finalize_into(output);
    return GC_OK;
}

pub unsafe fn gc_hmac_md5(
    mut key: *const libc::c_void,
    mut keylen: size_t,
    mut in_0: *const libc::c_void,
    mut inlen: size_t,
    mut resbuf: *mut libc::c_char,
) -> Gc_rc {
    type HmacMd5 = hmac::Hmac<md5::Md5>;
    let key = std::slice::from_raw_parts(key as *const u8, keylen);

    if let Ok(mut hasher) = <HmacMd5 as Mac>::new_from_slice(key) {
        let input = std::slice::from_raw_parts(in_0 as *const u8, inlen);
        hasher.update(input);
        let hash = hasher.finalize().into_bytes();
        let output = std::slice::from_raw_parts_mut(resbuf as *mut u8, hash.len());
        output.copy_from_slice(&hash);
        GC_OK
    } else {
        GC_INVALID_HASH
    }
}

pub unsafe fn gc_hmac_sha1(
    mut key: *const libc::c_void,
    mut keylen: size_t,
    mut in_0: *const libc::c_void,
    mut inlen: size_t,
    mut resbuf: *mut libc::c_char,
) -> Gc_rc {
    type HmacSha1 = hmac::Hmac<sha1::Sha1>;
    let key = std::slice::from_raw_parts(key as *const u8, keylen);

    if let Ok(mut hasher) = <HmacSha1 as Mac>::new_from_slice(key) {
        let input = std::slice::from_raw_parts(in_0 as *const u8, inlen);
        hasher.update(input);
        let hash = hasher.finalize().into_bytes();
        let output = std::slice::from_raw_parts_mut(resbuf as *mut u8, hash.len());
        output.copy_from_slice(&hash);
        GC_OK
    } else {
        GC_INVALID_HASH
    }
}

pub unsafe fn gc_hmac_sha256(
    mut key: *const libc::c_void,
    mut keylen: size_t,
    mut in_0: *const libc::c_void,
    mut inlen: size_t,
    mut resbuf: *mut libc::c_char,
) -> Gc_rc {
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let key = std::slice::from_raw_parts(key as *const u8, keylen);

    if let Ok(mut hasher) = <HmacSha256 as Mac>::new_from_slice(key) {
        let input = std::slice::from_raw_parts(in_0 as *const u8, inlen);
        hasher.update(input);
        let hash = hasher.finalize().into_bytes();
        let output = std::slice::from_raw_parts_mut(resbuf as *mut u8, hash.len());
        output.copy_from_slice(&hash);
        GC_OK
    } else {
        GC_INVALID_HASH
    }
}
