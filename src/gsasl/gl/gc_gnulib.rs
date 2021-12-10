use ::libc;
use libc::size_t;
use crate::gsasl::gc::{GC_INVALID_CIPHER, GC_INVALID_HASH, GC_MALLOC_ERROR, GC_OK, GC_RANDOM_ERROR,
                 Gc_rc};

extern "C" {
    fn calloc(_: size_t, _: size_t) -> *mut libc::c_void;
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

    fn rpl_free(ptr: *mut libc::c_void);

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: size_t)
     -> *mut libc::c_void;

    fn __errno_location() -> *mut libc::c_int;

    fn getrandom(__buffer: *mut libc::c_void, __length: size_t,
                 __flags: libc::c_uint) -> ssize_t;

    fn md5_init_ctx(ctx: *mut md5_ctx);

    fn md5_process_bytes(buffer: *const libc::c_void, len: size_t,
                         ctx: *mut md5_ctx);

    fn md5_finish_ctx(ctx: *mut md5_ctx, resbuf: *mut libc::c_void)
     -> *mut libc::c_void;

    fn md5_buffer(buffer: *const libc::c_char, len: size_t,
                  resblock: *mut libc::c_void) -> *mut libc::c_void;
    /* 128 bytes; the first buflen bytes are in use */
    /* Initialize structure containing state of computation. */

    fn sha1_init_ctx(ctx: *mut sha1_ctx);
    /* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is NOT required that LEN is a multiple of 64.  */

    fn sha1_process_bytes(buffer: *const libc::c_void, len: size_t,
                          ctx: *mut sha1_ctx);
    /* Process the remaining bytes in the buffer and put result from CTX
   in first 20 bytes following RESBUF.  The result is always in little
   endian byte order, so that a byte-wise output yields to the wanted
   ASCII representation of the message digest.  */

    fn sha1_finish_ctx(ctx: *mut sha1_ctx, resbuf: *mut libc::c_void)
     -> *mut libc::c_void;
    /* Compute SHA1 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */

    fn sha1_buffer(buffer: *const libc::c_char, len: size_t,
                   resblock: *mut libc::c_void) -> *mut libc::c_void;
    /* 128 bytes; the first buflen bytes are in use */
    /* Initialize structure containing state of computation. */

    fn sha256_init_ctx(ctx: *mut sha256_ctx);
    /* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is NOT required that LEN is a multiple of 64.  */

    fn sha256_process_bytes(buffer: *const libc::c_void, len: size_t,
                            ctx: *mut sha256_ctx);
    /* Process the remaining bytes in the buffer and put result from CTX
   in first 32 (28) bytes following RESBUF.  The result is always in little
   endian byte order, so that a byte-wise output yields to the wanted
   ASCII representation of the message digest.  */

    fn sha256_finish_ctx(ctx: *mut sha256_ctx, resbuf: *mut libc::c_void)
     -> *mut libc::c_void;
    /* Compute SHA256 (SHA224) message digest for LEN bytes beginning at BUFFER.
   The result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */

    fn sha256_buffer(buffer: *const libc::c_char, len: size_t,
                     resblock: *mut libc::c_void) -> *mut libc::c_void;
    /* hmac.h -- hashed message authentication codes
   Copyright (C) 2005, 2009-2021 Free Software Foundation, Inc.

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
    /* Written by Simon Josefsson.  */
    /* Compute Hashed Message Authentication Code with MD5, as described
   in RFC 2104, over BUFFER data of BUFLEN bytes using the KEY of
   KEYLEN bytes, writing the output to pre-allocated 16 byte minimum
   RESBUF buffer.  Return 0 on success.  */

    fn hmac_md5(key: *const libc::c_void, keylen: size_t,
                buffer: *const libc::c_void, buflen: size_t,
                resbuf: *mut libc::c_void) -> libc::c_int;
    /* Compute Hashed Message Authentication Code with SHA-1, over BUFFER
   data of BUFLEN bytes using the KEY of KEYLEN bytes, writing the
   output to pre-allocated 20 byte minimum RESBUF buffer.  Return 0 on
   success.  */

    fn hmac_sha1(key: *const libc::c_void, keylen: size_t,
                 in_0: *const libc::c_void, inlen: size_t,
                 resbuf: *mut libc::c_void) -> libc::c_int;
    /* Compute Hashed Message Authentication Code with SHA-256, over BUFFER
   data of BUFLEN bytes using the KEY of KEYLEN bytes, writing the
   output to pre-allocated 32 byte minimum RESBUF buffer.  Return 0 on
   success.  */

    fn hmac_sha256(key: *const libc::c_void, keylen: size_t,
                   in_0: *const libc::c_void, inlen: size_t,
                   resbuf: *mut libc::c_void) -> libc::c_int;
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
pub type gc_malloc_t
    =
    Option<unsafe fn(_: size_t) -> *mut libc::c_void>;
pub type gc_secure_check_t
    =
    Option<unsafe fn(_: *const libc::c_void) -> libc::c_int>;
pub type gc_realloc_t
    =
    Option<unsafe fn(_: *mut libc::c_void, _: size_t)
               -> *mut libc::c_void>;
pub type gc_free_t = Option<unsafe fn(_: *mut libc::c_void) -> ()>;
pub type ssize_t = __ssize_t;
pub type __ssize_t = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _gc_cipher_ctx {
    pub alg: Gc_cipher,
    pub mode: Gc_cipher_mode,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _gc_hash_ctx {
    pub alg: Gc_hash,
    pub mode: Gc_hash_mode,
    pub hash: [libc::c_char; 64],
    pub md5Context: md5_ctx,
    pub sha1Context: sha1_ctx,
    pub sha256Context: sha256_ctx,
}
/* Structure to save state of computation between the single steps.  */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha256_ctx {
    pub state: [uint32_t; 8],
    pub total: [uint32_t; 2],
    pub buflen: size_t,
    pub buffer: [uint32_t; 32],
}
pub type uint32_t = __uint32_t;
pub type __uint32_t = libc::c_uint;
/* Declarations of functions and data types used for SHA1 sum
   library functions.
   Copyright (C) 2000-2001, 2003, 2005-2006, 2008-2021 Free Software
   Foundation, Inc.

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
/* Structure to save state of computation between the single steps.  */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha1_ctx {
    pub A: uint32_t,
    pub B: uint32_t,
    pub C: uint32_t,
    pub D: uint32_t,
    pub E: uint32_t,
    pub total: [uint32_t; 2],
    pub buflen: uint32_t,
    pub buffer: [uint32_t; 32],
}
/* Declaration of functions and data types used for MD5 sum computing
   library functions.
   Copyright (C) 1995-1997, 1999-2001, 2004-2006, 2008-2021 Free Software
   Foundation, Inc.
   This file is part of the GNU C Library.

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
/* Structure to save state of computation between the single steps.  */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct md5_ctx {
    pub A: uint32_t,
    pub B: uint32_t,
    pub C: uint32_t,
    pub D: uint32_t,
    pub total: [uint32_t; 2],
    pub buflen: uint32_t,
    pub buffer: [uint32_t; 32],
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
/* Note: This file is only built if GC uses internal functions. */
/* Get prototype. */
/* For randomize. */
/* Hashes. */
/* Ciphers. */
#[no_mangle]
pub unsafe fn gc_init() -> Gc_rc { return GC_OK; }
#[no_mangle]
pub unsafe fn gc_done() { }
/* Overwrite BUFFER with random data, under the control of getrandom
   FLAGS.  BUFFER contains LENGTH bytes.  Inspired by getentropy,
   however LENGTH is not restricted to 256.  Return 0 on success, -1
   (setting errno) on failure.  */
unsafe fn randomize(mut buffer: *mut libc::c_void,
                               mut length: size_t, mut flags: libc::c_uint)
 -> libc::c_int {
    let mut buf: *mut libc::c_char = buffer as *mut libc::c_char;
    loop  {
        let mut bytes: ssize_t = 0;
        if length == 0 {
            return GC_OK as libc::c_int
        }
        loop  {
            bytes = getrandom(buf as *mut libc::c_void, length, flags);
            if !(bytes < 0 as libc::c_int as libc::c_long) { break ; }
            if *__errno_location() != 4 as libc::c_int {
                return GC_RANDOM_ERROR as libc::c_int
            }
        }
        if bytes == 0 as libc::c_int as libc::c_long { break ; }
        buf = buf.offset(bytes as isize);
        length =
            (length as libc::c_ulong).wrapping_sub(bytes as libc::c_ulong) as
                size_t as size_t
    }
    return GC_RANDOM_ERROR as libc::c_int;
}
/* Randomness. */
#[no_mangle]
pub unsafe fn gc_nonce(mut data: *mut libc::c_char,
                                  mut datalen: size_t) -> Gc_rc {
    return randomize(data as *mut libc::c_void, datalen,
                     0 as libc::c_int as libc::c_uint) as Gc_rc;
}
#[no_mangle]
pub unsafe fn gc_pseudo_random(mut data: *mut libc::c_char,
                                          mut datalen: size_t) -> Gc_rc {
    return randomize(data as *mut libc::c_void, datalen,
                     0 as libc::c_int as libc::c_uint) as Gc_rc;
}
#[no_mangle]
pub unsafe fn gc_random(mut data: *mut libc::c_char,
                                   mut datalen: size_t) -> Gc_rc {
    return randomize(data as *mut libc::c_void, datalen,
                     0x2 as libc::c_int as libc::c_uint) as Gc_rc;
}
/* Memory allocation. */
#[no_mangle]
pub unsafe fn gc_set_allocators(mut _func_malloc: gc_malloc_t,
                                           mut _secure_malloc: gc_malloc_t,
                                           mut _secure_check:
                                               gc_secure_check_t,
                                           mut _func_realloc: gc_realloc_t,
                                           mut _func_free: gc_free_t) {
}
/* Ciphers. */
#[no_mangle]
pub unsafe fn gc_cipher_open(mut alg: Gc_cipher,
                                        mut mode: Gc_cipher_mode,
                                        mut outhandle: *mut gc_cipher_handle)
 -> Gc_rc {
    let mut ctx: *mut _gc_cipher_ctx = 0 as *mut _gc_cipher_ctx;
    let mut rc: Gc_rc = GC_OK;
    ctx =
        calloc(::std::mem::size_of::<_gc_cipher_ctx>(), 1) as *mut _gc_cipher_ctx;
    if ctx.is_null() { return GC_MALLOC_ERROR }
    (*ctx).alg = alg;
    (*ctx).mode = mode;
    match alg as libc::c_uint { _ => { } }
    rc = GC_INVALID_CIPHER;
    if rc as libc::c_uint == GC_OK as libc::c_int as libc::c_uint {
        *outhandle = ctx as gc_cipher_handle
    } else { rpl_free(ctx as *mut libc::c_void); }
    return rc;
}
#[no_mangle]
pub unsafe fn gc_cipher_setkey(mut handle: gc_cipher_handle,
                                          mut _keylen: size_t,
                                          mut _key: *const libc::c_char)
 -> Gc_rc {
    let mut ctx: *mut _gc_cipher_ctx = handle as *mut _gc_cipher_ctx;
    match (*ctx).alg as libc::c_uint { _ => { } }
    return GC_INVALID_CIPHER;
}
#[no_mangle]
pub unsafe fn gc_cipher_setiv(mut handle: gc_cipher_handle,
                                         mut _ivlen: size_t,
                                         mut _iv: *const libc::c_char)
 -> Gc_rc {
    let mut ctx: *mut _gc_cipher_ctx = handle as *mut _gc_cipher_ctx;
    match (*ctx).alg as libc::c_uint { _ => { } }
    return GC_INVALID_CIPHER;
}
#[no_mangle]
pub unsafe fn gc_cipher_encrypt_inline(mut handle:
                                                      gc_cipher_handle,
                                                  mut _len: size_t,
                                                  mut _data: *mut libc::c_char)
 -> Gc_rc {
    let mut ctx: *mut _gc_cipher_ctx = handle as *mut _gc_cipher_ctx;
    match (*ctx).alg as libc::c_uint { _ => { } }
    return GC_INVALID_CIPHER;
}
#[no_mangle]
pub unsafe fn gc_cipher_decrypt_inline(mut handle:
                                                      gc_cipher_handle,
                                                  mut _len: size_t,
                                                  mut _data: *mut libc::c_char)
 -> Gc_rc {
    let mut ctx: *mut _gc_cipher_ctx = handle as *mut _gc_cipher_ctx;
    match (*ctx).alg as libc::c_uint { _ => { } }
    return GC_INVALID_CIPHER;
}
#[no_mangle]
pub unsafe fn gc_cipher_close(mut handle: gc_cipher_handle)
 -> Gc_rc {
    let mut ctx: *mut _gc_cipher_ctx = handle as *mut _gc_cipher_ctx;
    rpl_free(ctx as *mut libc::c_void);
    return GC_OK;
}
/* Hashes. */
#[no_mangle]
pub unsafe fn gc_hash_open(mut hash: Gc_hash,
                                      mut mode: Gc_hash_mode,
                                      mut outhandle: *mut gc_hash_handle)
 -> Gc_rc {
    let mut ctx: *mut _gc_hash_ctx = 0 as *mut _gc_hash_ctx;
    let mut rc: Gc_rc = GC_OK;
    if mode as libc::c_uint != 0 as libc::c_int as libc::c_uint {
        return GC_INVALID_HASH
    }
    ctx =
        calloc(::std::mem::size_of::<_gc_hash_ctx>(), 1) as *mut _gc_hash_ctx;
    if ctx.is_null() { return GC_MALLOC_ERROR }
    (*ctx).alg = hash;
    (*ctx).mode = mode;
    match hash as libc::c_uint {
        1 => { md5_init_ctx(&mut (*ctx).md5Context); }
        2 => { sha1_init_ctx(&mut (*ctx).sha1Context); }
        5 => { sha256_init_ctx(&mut (*ctx).sha256Context); }
        _ => { rc = GC_INVALID_HASH }
    }
    if rc as libc::c_uint == GC_OK as libc::c_int as libc::c_uint {
        *outhandle = ctx as gc_hash_handle
    } else { rpl_free(ctx as *mut libc::c_void); }
    return rc;
}
#[no_mangle]
pub unsafe fn gc_hash_clone(mut handle: gc_hash_handle,
                                       mut outhandle: *mut gc_hash_handle)
 -> Gc_rc {
    let mut in_0: *mut _gc_hash_ctx = handle as *mut _gc_hash_ctx;
    let mut out: *mut _gc_hash_ctx = 0 as *mut _gc_hash_ctx;
    out =
        calloc(::std::mem::size_of::<_gc_hash_ctx>(), 1) as *mut _gc_hash_ctx;
    *outhandle = out as gc_hash_handle;
    if out.is_null() { return GC_MALLOC_ERROR }
    memcpy(out as *mut libc::c_void, in_0 as *const libc::c_void,
           ::std::mem::size_of::<_gc_hash_ctx>());
    return GC_OK;
}
#[no_mangle]
pub unsafe fn gc_hash_digest_length(mut hash: Gc_hash) -> size_t {
    let mut len: size_t = 0;
    match hash as libc::c_uint {
        3 => { len = 16 as libc::c_int as size_t }
        0 => { len = 16 as libc::c_int as size_t }
        1 => { len = 16 as libc::c_int as size_t }
        4 => { len = 20 as libc::c_int as size_t }
        2 => { len = 20 as libc::c_int as size_t }
        5 => { len = 32 as libc::c_int as size_t }
        7 => { len = 64 as libc::c_int as size_t }
        9 => { len = 32 as libc::c_int as size_t }
        _ => { return 0 as libc::c_int as size_t }
    }
    return len;
}
#[no_mangle]
pub unsafe fn gc_hash_write(mut handle: gc_hash_handle,
                                       mut len: size_t,
                                       mut data: *const libc::c_char) {
    let mut ctx: *mut _gc_hash_ctx = handle as *mut _gc_hash_ctx;
    match (*ctx).alg as libc::c_uint {
        1 => {
            md5_process_bytes(data as *const libc::c_void, len,
                              &mut (*ctx).md5Context);
        }
        2 => {
            sha1_process_bytes(data as *const libc::c_void, len,
                               &mut (*ctx).sha1Context);
        }
        5 => {
            sha256_process_bytes(data as *const libc::c_void, len,
                                 &mut (*ctx).sha256Context);
        }
        _ => { }
    };
}
#[no_mangle]
pub unsafe fn gc_hash_read(mut handle: gc_hash_handle)
 -> *const libc::c_char {
    let mut ctx: *mut _gc_hash_ctx = handle as *mut _gc_hash_ctx;
    let mut ret: *const libc::c_char = 0 as *const libc::c_char;
    match (*ctx).alg as libc::c_uint {
        1 => {
            md5_finish_ctx(&mut (*ctx).md5Context,
                           (*ctx).hash.as_mut_ptr() as *mut libc::c_void);
            ret = (*ctx).hash.as_mut_ptr()
        }
        2 => {
            sha1_finish_ctx(&mut (*ctx).sha1Context,
                            (*ctx).hash.as_mut_ptr() as *mut libc::c_void);
            ret = (*ctx).hash.as_mut_ptr()
        }
        5 => {
            sha256_finish_ctx(&mut (*ctx).sha256Context,
                              (*ctx).hash.as_mut_ptr() as *mut libc::c_void);
            ret = (*ctx).hash.as_mut_ptr()
        }
        _ => { return 0 as *const libc::c_char }
    }
    return ret;
}
#[no_mangle]
pub unsafe fn gc_hash_close(mut handle: gc_hash_handle) {
    let mut ctx: *mut _gc_hash_ctx = handle as *mut _gc_hash_ctx;
    rpl_free(ctx as *mut libc::c_void);
}
/* Compute a hash value over buffer IN of INLEN bytes size using the
   algorithm HASH, placing the result in the pre-allocated buffer OUT.
   The required size of OUT depends on HASH, and is generally
   GC_<HASH>_DIGEST_SIZE.  For example, for GC_MD5 the output buffer
   must be 16 bytes.  The return value is 0 (GC_OK) on success, or
   another Gc_rc error code. */
#[no_mangle]
pub unsafe fn gc_hash_buffer(mut hash: Gc_hash,
                                        mut in_0: *const libc::c_void,
                                        mut inlen: size_t,
                                        mut resbuf: *mut libc::c_char)
 -> Gc_rc {
    match hash as libc::c_uint {
        1 => {
            md5_buffer(in_0 as *const libc::c_char, inlen,
                       resbuf as *mut libc::c_void);
        }
        2 => {
            sha1_buffer(in_0 as *const libc::c_char, inlen,
                        resbuf as *mut libc::c_void);
        }
        5 => {
            sha256_buffer(in_0 as *const libc::c_char, inlen,
                          resbuf as *mut libc::c_void);
        }
        _ => { return GC_INVALID_HASH }
    }
    return GC_OK;
}
#[no_mangle]
pub unsafe fn gc_md5(mut in_0: *const libc::c_void,
                                mut inlen: size_t,
                                mut resbuf: *mut libc::c_void) -> Gc_rc {
    md5_buffer(in_0 as *const libc::c_char, inlen, resbuf);
    return GC_OK;
}
#[no_mangle]
pub unsafe fn gc_sha1(mut in_0: *const libc::c_void,
                                 mut inlen: size_t,
                                 mut resbuf: *mut libc::c_void) -> Gc_rc {
    sha1_buffer(in_0 as *const libc::c_char, inlen, resbuf);
    return GC_OK;
}
#[no_mangle]
pub unsafe fn gc_sha256(mut in_0: *const libc::c_void,
                                   mut inlen: size_t,
                                   mut resbuf: *mut libc::c_void) -> Gc_rc {
    sha256_buffer(in_0 as *const libc::c_char, inlen, resbuf);
    return GC_OK;
}
#[no_mangle]
pub unsafe fn gc_hmac_md5(mut key: *const libc::c_void,
                                     mut keylen: size_t,
                                     mut in_0: *const libc::c_void,
                                     mut inlen: size_t,
                                     mut resbuf: *mut libc::c_char) -> Gc_rc {
    hmac_md5(key, keylen, in_0, inlen, resbuf as *mut libc::c_void);
    return GC_OK;
}
#[no_mangle]
pub unsafe fn gc_hmac_sha1(mut key: *const libc::c_void,
                                      mut keylen: size_t,
                                      mut in_0: *const libc::c_void,
                                      mut inlen: size_t,
                                      mut resbuf: *mut libc::c_char)
 -> Gc_rc {
    hmac_sha1(key, keylen, in_0, inlen, resbuf as *mut libc::c_void);
    return GC_OK;
}
#[no_mangle]
pub unsafe fn gc_hmac_sha256(mut key: *const libc::c_void,
                                        mut keylen: size_t,
                                        mut in_0: *const libc::c_void,
                                        mut inlen: size_t,
                                        mut resbuf: *mut libc::c_char)
 -> Gc_rc {
    hmac_sha256(key, keylen, in_0, inlen, resbuf as *mut libc::c_void);
    return GC_OK;
}
