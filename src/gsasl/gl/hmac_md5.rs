use ::libc;
use libc::size_t;
extern "C" {
    fn md5_init_ctx(ctx: *mut md5_ctx);

    fn md5_process_block(buffer: *const libc::c_void, len: size_t,
                         ctx: *mut md5_ctx);

    fn md5_process_bytes(buffer: *const libc::c_void, len: size_t,
                         ctx: *mut md5_ctx);

    fn md5_finish_ctx(ctx: *mut md5_ctx, resbuf: *mut libc::c_void)
     -> *mut libc::c_void;

    fn memset(_: *mut libc::c_void, _: libc::c_int, _: size_t)
     -> *mut libc::c_void;
    /* memxor.h -- perform binary exclusive OR operation on memory blocks.
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
    /* Written by Simon Josefsson.  The interface was inspired by memxor
   in Niels Möller's Nettle. */
    /* Compute binary exclusive OR of memory areas DEST and SRC, putting
   the result in DEST, of length N bytes.  Returns a pointer to
   DEST. */

    fn memxor(dest: *mut libc::c_void, src: *const libc::c_void, n: size_t)
     -> *mut libc::c_void;
}

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
pub type uint32_t = __uint32_t;
pub type __uint32_t = libc::c_uint;
/* Concatenate two preprocessor tokens.  */
unsafe extern "C" fn hmac_hash(mut key: *const libc::c_void,
                               mut keylen: size_t,
                               mut in_0: *const libc::c_void,
                               mut inlen: size_t, mut pad: libc::c_int,
                               mut resbuf: *mut libc::c_void) {
    let mut hmac_ctx: md5_ctx =
        md5_ctx{A: 0,
                B: 0,
                C: 0,
                D: 0,
                total: [0; 2],
                buflen: 0,
                buffer: [0; 32],};
    let mut block: [libc::c_char; 64] = [0; 64];
    memset(block.as_mut_ptr() as *mut libc::c_void, pad, ::std::mem::size_of::<[libc::c_char; 64]>());
    memxor(block.as_mut_ptr() as *mut libc::c_void, key, keylen);
    md5_init_ctx(&mut hmac_ctx);
    md5_process_block(block.as_mut_ptr() as *const libc::c_void,
                      ::std::mem::size_of::<[libc::c_char; 64]>(), &mut hmac_ctx);
    md5_process_bytes(in_0, inlen, &mut hmac_ctx);
    md5_finish_ctx(&mut hmac_ctx, resbuf);
}
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
#[no_mangle]
pub unsafe extern "C" fn hmac_md5(mut key: *const libc::c_void,
                                  mut keylen: size_t,
                                  mut in_0: *const libc::c_void,
                                  mut inlen: size_t,
                                  mut resbuf: *mut libc::c_void)
 -> libc::c_int {
    let mut optkeybuf: [libc::c_char; 16] = [0; 16];
    let mut innerhash: [libc::c_char; 16] = [0; 16];
    /* Ensure key size is <= block size.  */
    if keylen > 64 {
        let mut keyhash: md5_ctx =
            md5_ctx{A: 0,
                    B: 0,
                    C: 0,
                    D: 0,
                    total: [0; 2],
                    buflen: 0,
                    buffer: [0; 32],};
        md5_init_ctx(&mut keyhash);
        md5_process_bytes(key, keylen, &mut keyhash);
        md5_finish_ctx(&mut keyhash,
                       optkeybuf.as_mut_ptr() as *mut libc::c_void);
        key = optkeybuf.as_mut_ptr() as *const libc::c_void;
        /* zero padding of the key to the block size
         is implicit in the memxor.  */
        keylen = ::std::mem::size_of::<[libc::c_char; 16]>()
    }
    /* Compute INNERHASH from KEY and IN.  */
    hmac_hash(key, keylen, in_0, inlen, 0x36 as libc::c_int,
              innerhash.as_mut_ptr() as *mut libc::c_void);
    /* Compute result from KEY and INNERHASH.  */
    hmac_hash(key, keylen, innerhash.as_mut_ptr() as *const libc::c_void,
              ::std::mem::size_of::<[libc::c_char; 16]>(),
              0x5c as libc::c_int, resbuf);
    return 0 as libc::c_int;
}
