use ::libc;
use ::c2rust_asm_casts;
use c2rust_asm_casts::AsmCastTrait;
extern "C" {
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type uint32_t = __uint32_t;
pub type uintptr_t = libc::c_ulong;
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
/* This array contains the bytes used to pad the buffer to the next
   64-byte boundary.  (RFC 1321, 3.1: Step 1)  */
static mut fillbuf: [libc::c_uchar; 64] =
    [0x80 as libc::c_int as libc::c_uchar, 0 as libc::c_int as libc::c_uchar,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/* Take a pointer to a 160 bit block of data (five 32 bit ints) and
   initialize it to the start constants of the SHA1 algorithm.  This
   must be called before using hash in the call to sha1_hash.  */
#[no_mangle]
pub unsafe extern "C" fn sha1_init_ctx(mut ctx: *mut sha1_ctx) {
    (*ctx).A = 0x67452301 as libc::c_int as uint32_t;
    (*ctx).B = 0xefcdab89 as libc::c_uint;
    (*ctx).C = 0x98badcfe as libc::c_uint;
    (*ctx).D = 0x10325476 as libc::c_int as uint32_t;
    (*ctx).E = 0xc3d2e1f0 as libc::c_uint;
    (*ctx).total[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    (*ctx).total[0 as libc::c_int as usize] =
        (*ctx).total[1 as libc::c_int as usize];
    (*ctx).buflen = 0 as libc::c_int as uint32_t;
}
/* Copy the 4 byte value from v into the memory location pointed to by *cp,
   If your architecture allows unaligned access this is equivalent to
   * (uint32_t *) cp = v  */
unsafe extern "C" fn set_uint32(mut cp: *mut libc::c_char, mut v: uint32_t) {
    memcpy(cp as *mut libc::c_void,
           &mut v as *mut uint32_t as *const libc::c_void,
           ::std::mem::size_of::<uint32_t>() as libc::c_ulong);
}
/* Put result from CTX in first 20 bytes following RESBUF.  The result
   must be in little endian byte order.  */
#[no_mangle]
pub unsafe extern "C" fn sha1_read_ctx(mut ctx: *const sha1_ctx,
                                       mut resbuf: *mut libc::c_void)
 -> *mut libc::c_void {
    let mut r: *mut libc::c_char = resbuf as *mut libc::c_char;
    set_uint32(r.offset((0 as libc::c_int as
                             libc::c_ulong).wrapping_mul(::std::mem::size_of::<uint32_t>()
                                                             as libc::c_ulong)
                            as isize),
               ({
                    let mut __v: libc::c_uint = 0;
                    let mut __x: libc::c_uint = (*ctx).A;
                    if 0 != 0 {
                        __v =
                            (__x & 0xff000000 as libc::c_uint) >>
                                24 as libc::c_int |
                                (__x &
                                     0xff0000 as libc::c_int as libc::c_uint)
                                    >> 8 as libc::c_int |
                                (__x & 0xff00 as libc::c_int as libc::c_uint)
                                    << 8 as libc::c_int |
                                (__x & 0xff as libc::c_int as libc::c_uint) <<
                                    24 as libc::c_int
                    } else {
                        let fresh0 = &mut __v;
                        let fresh1;
                        let fresh2 = __x;
                        asm!("bswap $0" : "=r" (fresh1) : "0"
                             (c2rust_asm_casts::AsmCast::cast_in(fresh0, fresh2))
                             :);
                        c2rust_asm_casts::AsmCast::cast_out(fresh0, fresh2,
                                                            fresh1);
                    }
                    __v
                }));
    set_uint32(r.offset((1 as libc::c_int as
                             libc::c_ulong).wrapping_mul(::std::mem::size_of::<uint32_t>()
                                                             as libc::c_ulong)
                            as isize),
               ({
                    let mut __v: libc::c_uint = 0;
                    let mut __x: libc::c_uint = (*ctx).B;
                    if 0 != 0 {
                        __v =
                            (__x & 0xff000000 as libc::c_uint) >>
                                24 as libc::c_int |
                                (__x &
                                     0xff0000 as libc::c_int as libc::c_uint)
                                    >> 8 as libc::c_int |
                                (__x & 0xff00 as libc::c_int as libc::c_uint)
                                    << 8 as libc::c_int |
                                (__x & 0xff as libc::c_int as libc::c_uint) <<
                                    24 as libc::c_int
                    } else {
                        let fresh3 = &mut __v;
                        let fresh4;
                        let fresh5 = __x;
                        asm!("bswap $0" : "=r" (fresh4) : "0"
                             (c2rust_asm_casts::AsmCast::cast_in(fresh3, fresh5))
                             :);
                        c2rust_asm_casts::AsmCast::cast_out(fresh3, fresh5,
                                                            fresh4);
                    }
                    __v
                }));
    set_uint32(r.offset((2 as libc::c_int as
                             libc::c_ulong).wrapping_mul(::std::mem::size_of::<uint32_t>()
                                                             as libc::c_ulong)
                            as isize),
               ({
                    let mut __v: libc::c_uint = 0;
                    let mut __x: libc::c_uint = (*ctx).C;
                    if 0 != 0 {
                        __v =
                            (__x & 0xff000000 as libc::c_uint) >>
                                24 as libc::c_int |
                                (__x &
                                     0xff0000 as libc::c_int as libc::c_uint)
                                    >> 8 as libc::c_int |
                                (__x & 0xff00 as libc::c_int as libc::c_uint)
                                    << 8 as libc::c_int |
                                (__x & 0xff as libc::c_int as libc::c_uint) <<
                                    24 as libc::c_int
                    } else {
                        let fresh6 = &mut __v;
                        let fresh7;
                        let fresh8 = __x;
                        asm!("bswap $0" : "=r" (fresh7) : "0"
                             (c2rust_asm_casts::AsmCast::cast_in(fresh6, fresh8))
                             :);
                        c2rust_asm_casts::AsmCast::cast_out(fresh6, fresh8,
                                                            fresh7);
                    }
                    __v
                }));
    set_uint32(r.offset((3 as libc::c_int as
                             libc::c_ulong).wrapping_mul(::std::mem::size_of::<uint32_t>()
                                                             as libc::c_ulong)
                            as isize),
               ({
                    let mut __v: libc::c_uint = 0;
                    let mut __x: libc::c_uint = (*ctx).D;
                    if 0 != 0 {
                        __v =
                            (__x & 0xff000000 as libc::c_uint) >>
                                24 as libc::c_int |
                                (__x &
                                     0xff0000 as libc::c_int as libc::c_uint)
                                    >> 8 as libc::c_int |
                                (__x & 0xff00 as libc::c_int as libc::c_uint)
                                    << 8 as libc::c_int |
                                (__x & 0xff as libc::c_int as libc::c_uint) <<
                                    24 as libc::c_int
                    } else {
                        let fresh9 = &mut __v;
                        let fresh10;
                        let fresh11 = __x;
                        asm!("bswap $0" : "=r" (fresh10) : "0"
                             (c2rust_asm_casts::AsmCast::cast_in(fresh9, fresh11))
                             :);
                        c2rust_asm_casts::AsmCast::cast_out(fresh9, fresh11,
                                                            fresh10);
                    }
                    __v
                }));
    set_uint32(r.offset((4 as libc::c_int as
                             libc::c_ulong).wrapping_mul(::std::mem::size_of::<uint32_t>()
                                                             as libc::c_ulong)
                            as isize),
               ({
                    let mut __v: libc::c_uint = 0;
                    let mut __x: libc::c_uint = (*ctx).E;
                    if 0 != 0 {
                        __v =
                            (__x & 0xff000000 as libc::c_uint) >>
                                24 as libc::c_int |
                                (__x &
                                     0xff0000 as libc::c_int as libc::c_uint)
                                    >> 8 as libc::c_int |
                                (__x & 0xff00 as libc::c_int as libc::c_uint)
                                    << 8 as libc::c_int |
                                (__x & 0xff as libc::c_int as libc::c_uint) <<
                                    24 as libc::c_int
                    } else {
                        let fresh12 = &mut __v;
                        let fresh13;
                        let fresh14 = __x;
                        asm!("bswap $0" : "=r" (fresh13) : "0"
                             (c2rust_asm_casts::AsmCast::cast_in(fresh12, fresh14))
                             :);
                        c2rust_asm_casts::AsmCast::cast_out(fresh12, fresh14,
                                                            fresh13);
                    }
                    __v
                }));
    return resbuf;
}
/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.  */
#[no_mangle]
pub unsafe extern "C" fn sha1_finish_ctx(mut ctx: *mut sha1_ctx,
                                         mut resbuf: *mut libc::c_void)
 -> *mut libc::c_void {
    /* Take yet unprocessed bytes into account.  */
    let mut bytes: uint32_t = (*ctx).buflen;
    let mut size: size_t =
        if bytes < 56 as libc::c_int as libc::c_uint {
            (64 as libc::c_int) / 4 as libc::c_int
        } else { (64 as libc::c_int * 2 as libc::c_int) / 4 as libc::c_int }
            as size_t;
    /* Now count remaining bytes.  */
    (*ctx).total[0 as libc::c_int as usize] =
        ((*ctx).total[0 as libc::c_int as usize] as
             libc::c_uint).wrapping_add(bytes) as uint32_t as uint32_t;
    if (*ctx).total[0 as libc::c_int as usize] < bytes {
        (*ctx).total[1 as libc::c_int as usize] =
            (*ctx).total[1 as libc::c_int as usize].wrapping_add(1)
    }
    /* Put the 64-bit file length in *bits* at the end of the buffer.  */
    (*ctx).buffer[size.wrapping_sub(2 as libc::c_int as libc::c_ulong) as
                      usize] =
        ({
             let mut __v: libc::c_uint = 0;
             let mut __x: libc::c_uint =
                 (*ctx).total[1 as libc::c_int as usize] << 3 as libc::c_int |
                     (*ctx).total[0 as libc::c_int as usize] >>
                         29 as libc::c_int;
             if 0 != 0 {
                 __v =
                     (__x & 0xff000000 as libc::c_uint) >> 24 as libc::c_int |
                         (__x & 0xff0000 as libc::c_int as libc::c_uint) >>
                             8 as libc::c_int |
                         (__x & 0xff00 as libc::c_int as libc::c_uint) <<
                             8 as libc::c_int |
                         (__x & 0xff as libc::c_int as libc::c_uint) <<
                             24 as libc::c_int
             } else {
                 let fresh15 = &mut __v;
                 let fresh16;
                 let fresh17 = __x;
                 asm!("bswap $0" : "=r" (fresh16) : "0"
                      (c2rust_asm_casts::AsmCast::cast_in(fresh15, fresh17))
                      :);
                 c2rust_asm_casts::AsmCast::cast_out(fresh15, fresh17,
                                                     fresh16);
             }
             __v
         });
    (*ctx).buffer[size.wrapping_sub(1 as libc::c_int as libc::c_ulong) as
                      usize] =
        ({
             let mut __v: libc::c_uint = 0;
             let mut __x: libc::c_uint =
                 (*ctx).total[0 as libc::c_int as usize] << 3 as libc::c_int;
             if 0 != 0 {
                 __v =
                     (__x & 0xff000000 as libc::c_uint) >> 24 as libc::c_int |
                         (__x & 0xff0000 as libc::c_int as libc::c_uint) >>
                             8 as libc::c_int |
                         (__x & 0xff00 as libc::c_int as libc::c_uint) <<
                             8 as libc::c_int |
                         (__x & 0xff as libc::c_int as libc::c_uint) <<
                             24 as libc::c_int
             } else {
                 let fresh18 = &mut __v;
                 let fresh19;
                 let fresh20 = __x;
                 asm!("bswap $0" : "=r" (fresh19) : "0"
                      (c2rust_asm_casts::AsmCast::cast_in(fresh18, fresh20))
                      :);
                 c2rust_asm_casts::AsmCast::cast_out(fresh18, fresh20,
                                                     fresh19);
             }
             __v
         });
    memcpy(&mut *((*ctx).buffer.as_mut_ptr() as
                      *mut libc::c_char).offset(bytes as isize) as
               *mut libc::c_char as *mut libc::c_void,
           fillbuf.as_ptr() as *const libc::c_void,
           size.wrapping_sub(2 as libc::c_int as
                                 libc::c_ulong).wrapping_mul(4 as libc::c_int
                                                                 as
                                                                 libc::c_ulong).wrapping_sub(bytes
                                                                                                 as
                                                                                                 libc::c_ulong));
    /* Process last bytes.  */
    sha1_process_block((*ctx).buffer.as_mut_ptr() as *const libc::c_void,
                       size.wrapping_mul(4 as libc::c_int as libc::c_ulong),
                       ctx);
    return sha1_read_ctx(ctx, resbuf);
}
/* Process the remaining bytes in the buffer and put result from CTX
   in first 20 bytes following RESBUF.  The result is always in little
   endian byte order, so that a byte-wise output yields to the wanted
   ASCII representation of the message digest.  */
/* Put result from CTX in first 20 bytes following RESBUF.  The result is
   always in little endian byte order, so that a byte-wise output yields
   to the wanted ASCII representation of the message digest.  */
/* Compute SHA1 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
/* Compute SHA1 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
#[no_mangle]
pub unsafe extern "C" fn sha1_buffer(mut buffer: *const libc::c_char,
                                     mut len: size_t,
                                     mut resblock: *mut libc::c_void)
 -> *mut libc::c_void {
    let mut ctx: sha1_ctx =
        sha1_ctx{A: 0,
                 B: 0,
                 C: 0,
                 D: 0,
                 E: 0,
                 total: [0; 2],
                 buflen: 0,
                 buffer: [0; 32],};
    /* Initialize the computation context.  */
    sha1_init_ctx(&mut ctx);
    /* Process whole buffer but last len % 64 bytes.  */
    sha1_process_bytes(buffer as *const libc::c_void, len, &mut ctx);
    /* Put result in desired memory area.  */
    return sha1_finish_ctx(&mut ctx, resblock);
}
/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is NOT required that LEN is a multiple of 64.  */
#[no_mangle]
pub unsafe extern "C" fn sha1_process_bytes(mut buffer: *const libc::c_void,
                                            mut len: size_t,
                                            mut ctx: *mut sha1_ctx) {
    /* When we already have some bits in our internal buffer concatenate
     both inputs first.  */
    if (*ctx).buflen != 0 as libc::c_int as libc::c_uint {
        let mut left_over: size_t = (*ctx).buflen as size_t;
        let mut add: size_t =
            if (128 as libc::c_int as libc::c_ulong).wrapping_sub(left_over) >
                   len {
                len
            } else {
                (128 as libc::c_int as libc::c_ulong).wrapping_sub(left_over)
            };
        memcpy(&mut *((*ctx).buffer.as_mut_ptr() as
                          *mut libc::c_char).offset(left_over as isize) as
                   *mut libc::c_char as *mut libc::c_void, buffer, add);
        (*ctx).buflen =
            ((*ctx).buflen as libc::c_ulong).wrapping_add(add) as uint32_t as
                uint32_t;
        if (*ctx).buflen > 64 as libc::c_int as libc::c_uint {
            sha1_process_block((*ctx).buffer.as_mut_ptr() as
                                   *const libc::c_void,
                               ((*ctx).buflen &
                                    !(63 as libc::c_int) as libc::c_uint) as
                                   size_t, ctx);
            (*ctx).buflen &= 63 as libc::c_int as libc::c_uint;
            /* The regions in the following copy operation cannot overlap,
             because ctx->buflen < 64 ≤ (left_over + add) & ~63.  */
            memcpy((*ctx).buffer.as_mut_ptr() as *mut libc::c_void,
                   &mut *((*ctx).buffer.as_mut_ptr() as
                              *mut libc::c_char).offset((left_over.wrapping_add(add)
                                                             &
                                                             !(63 as
                                                                   libc::c_int)
                                                                 as
                                                                 libc::c_ulong)
                                                            as isize) as
                       *mut libc::c_char as *const libc::c_void,
                   (*ctx).buflen as libc::c_ulong);
        }
        buffer =
            (buffer as *const libc::c_char).offset(add as isize) as
                *const libc::c_void;
        len = (len as libc::c_ulong).wrapping_sub(add) as size_t as size_t
    }
    /* Process available complete blocks.  */
    if len >= 64 as libc::c_int as libc::c_ulong {
        if (buffer as
                uintptr_t).wrapping_rem(::std::mem::align_of::<uint32_t>() as
                                            libc::c_ulong) !=
               0 as libc::c_int as libc::c_ulong {
            while len > 64 as libc::c_int as libc::c_ulong {
                sha1_process_block(memcpy((*ctx).buffer.as_mut_ptr() as
                                              *mut libc::c_void, buffer,
                                          64 as libc::c_int as libc::c_ulong),
                                   64 as libc::c_int as size_t, ctx);
                buffer =
                    (buffer as
                         *const libc::c_char).offset(64 as libc::c_int as
                                                         isize) as
                        *const libc::c_void;
                len =
                    (len as
                         libc::c_ulong).wrapping_sub(64 as libc::c_int as
                                                         libc::c_ulong) as
                        size_t as size_t
            }
        } else {
            sha1_process_block(buffer,
                               len & !(63 as libc::c_int) as libc::c_ulong,
                               ctx);
            buffer =
                (buffer as
                     *const libc::c_char).offset((len &
                                                      !(63 as libc::c_int) as
                                                          libc::c_ulong) as
                                                     isize) as
                    *const libc::c_void;
            len &= 63 as libc::c_int as libc::c_ulong
        }
    }
    /* Move remaining bytes in internal buffer.  */
    if len > 0 as libc::c_int as libc::c_ulong {
        let mut left_over_0: size_t = (*ctx).buflen as size_t;
        memcpy(&mut *((*ctx).buffer.as_mut_ptr() as
                          *mut libc::c_char).offset(left_over_0 as isize) as
                   *mut libc::c_char as *mut libc::c_void, buffer, len);
        left_over_0 =
            (left_over_0 as libc::c_ulong).wrapping_add(len) as size_t as
                size_t;
        if left_over_0 >= 64 as libc::c_int as libc::c_ulong {
            sha1_process_block((*ctx).buffer.as_mut_ptr() as
                                   *const libc::c_void,
                               64 as libc::c_int as size_t, ctx);
            left_over_0 =
                (left_over_0 as
                     libc::c_ulong).wrapping_sub(64 as libc::c_int as
                                                     libc::c_ulong) as size_t
                    as size_t;
            /* The regions in the following copy operation cannot overlap,
             because left_over ≤ 64.  */
            memcpy((*ctx).buffer.as_mut_ptr() as *mut libc::c_void,
                   &mut *(*ctx).buffer.as_mut_ptr().offset(16 as libc::c_int
                                                               as isize) as
                       *mut uint32_t as *const libc::c_void, left_over_0);
        }
        (*ctx).buflen = left_over_0 as uint32_t
    };
}
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
/* ≥ 0, ≤ 128 */
/* 128 bytes; the first buflen bytes are in use */
/* Initialize structure containing state of computation. */
/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is necessary that LEN is a multiple of 64!!! */
/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0.
   Most of this code comes from GnuPG's cipher/sha1.c.  */
#[no_mangle]
pub unsafe extern "C" fn sha1_process_block(mut buffer: *const libc::c_void,
                                            mut len: size_t,
                                            mut ctx: *mut sha1_ctx) {
    let mut words: *const uint32_t = buffer as *const uint32_t;
    let mut nwords: size_t =
        len.wrapping_div(::std::mem::size_of::<uint32_t>() as libc::c_ulong);
    let mut endp: *const uint32_t = words.offset(nwords as isize);
    let mut x: [uint32_t; 16] = [0; 16];
    let mut a: uint32_t = (*ctx).A;
    let mut b: uint32_t = (*ctx).B;
    let mut c: uint32_t = (*ctx).C;
    let mut d: uint32_t = (*ctx).D;
    let mut e: uint32_t = (*ctx).E;
    let mut lolen: uint32_t = len as uint32_t;
    /* First increment the byte count.  RFC 1321 specifies the possible
     length of the file up to 2^64 bits.  Here we only compute the
     number of bytes.  Do a double word increment.  */
    (*ctx).total[0 as libc::c_int as usize] =
        ((*ctx).total[0 as libc::c_int as usize] as
             libc::c_uint).wrapping_add(lolen) as uint32_t as uint32_t;
    (*ctx).total[1 as libc::c_int as usize] =
        ((*ctx).total[1 as libc::c_int as usize] as
             libc::c_ulong).wrapping_add((len >> 31 as libc::c_int >>
                                              1 as
                                                  libc::c_int).wrapping_add(((*ctx).total[0
                                                                                              as
                                                                                              libc::c_int
                                                                                              as
                                                                                              usize]
                                                                                 <
                                                                                 lolen)
                                                                                as
                                                                                libc::c_int
                                                                                as
                                                                                libc::c_ulong))
            as uint32_t as uint32_t;
    while words < endp {
        let mut tm: uint32_t = 0;
        let mut t: libc::c_int = 0;
        t = 0 as libc::c_int;
        while t < 16 as libc::c_int {
            x[t as usize] =
                ({
                     let mut __v: libc::c_uint = 0;
                     let mut __x: libc::c_uint = *words;
                     if 0 != 0 {
                         __v =
                             (__x & 0xff000000 as libc::c_uint) >>
                                 24 as libc::c_int |
                                 (__x &
                                      0xff0000 as libc::c_int as libc::c_uint)
                                     >> 8 as libc::c_int |
                                 (__x & 0xff00 as libc::c_int as libc::c_uint)
                                     << 8 as libc::c_int |
                                 (__x & 0xff as libc::c_int as libc::c_uint)
                                     << 24 as libc::c_int
                     } else {
                         let fresh21 = &mut __v;
                         let fresh22;
                         let fresh23 = __x;
                         asm!("bswap $0" : "=r" (fresh22) : "0"
                              (c2rust_asm_casts::AsmCast::cast_in(fresh21, fresh23))
                              :);
                         c2rust_asm_casts::AsmCast::cast_out(fresh21, fresh23,
                                                             fresh22);
                     }
                     __v
                 });
            words = words.offset(1);
            t += 1
        }
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           ^
                                                                                           b
                                                                                               &
                                                                                               (c
                                                                                                    ^
                                                                                                    d)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[0
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           ^
                                                                                           a
                                                                                               &
                                                                                               (b
                                                                                                    ^
                                                                                                    c)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[1
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           ^
                                                                                           e
                                                                                               &
                                                                                               (a
                                                                                                    ^
                                                                                                    b)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[2
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           ^
                                                                                           d
                                                                                               &
                                                                                               (e
                                                                                                    ^
                                                                                                    a)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[3
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           ^
                                                                                           c
                                                                                               &
                                                                                               (d
                                                                                                    ^
                                                                                                    e)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[4
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           ^
                                                                                           b
                                                                                               &
                                                                                               (c
                                                                                                    ^
                                                                                                    d)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[5
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           ^
                                                                                           a
                                                                                               &
                                                                                               (b
                                                                                                    ^
                                                                                                    c)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[6
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           ^
                                                                                           e
                                                                                               &
                                                                                               (a
                                                                                                    ^
                                                                                                    b)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[7
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           ^
                                                                                           d
                                                                                               &
                                                                                               (e
                                                                                                    ^
                                                                                                    a)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[8
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           ^
                                                                                           c
                                                                                               &
                                                                                               (d
                                                                                                    ^
                                                                                                    e)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[9
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           ^
                                                                                           b
                                                                                               &
                                                                                               (c
                                                                                                    ^
                                                                                                    d)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[10
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           ^
                                                                                           a
                                                                                               &
                                                                                               (b
                                                                                                    ^
                                                                                                    c)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[11
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           ^
                                                                                           e
                                                                                               &
                                                                                               (a
                                                                                                    ^
                                                                                                    b)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[12
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           ^
                                                                                           d
                                                                                               &
                                                                                               (e
                                                                                                    ^
                                                                                                    a)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[13
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           ^
                                                                                           c
                                                                                               &
                                                                                               (d
                                                                                                    ^
                                                                                                    e)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[14
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           ^
                                                                                           b
                                                                                               &
                                                                                               (c
                                                                                                    ^
                                                                                                    d)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[15
                                                                                                                                                          as
                                                                                                                                                          libc::c_int
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(16 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(16 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(16 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(16 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(16 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           ^
                                                                                           a
                                                                                               &
                                                                                               (b
                                                                                                    ^
                                                                                                    c)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(16
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(17 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(17 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(17 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(17 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(17 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           ^
                                                                                           e
                                                                                               &
                                                                                               (a
                                                                                                    ^
                                                                                                    b)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(17
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(18 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(18 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(18 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(18 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(18 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           ^
                                                                                           d
                                                                                               &
                                                                                               (e
                                                                                                    ^
                                                                                                    a)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(18
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(19 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(19 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(19 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(19 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(19 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           ^
                                                                                           c
                                                                                               &
                                                                                               (d
                                                                                                    ^
                                                                                                    e)).wrapping_add(0x5a827999
                                                                                                                         as
                                                                                                                         libc::c_int
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(19
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(20 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(20 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(20 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(20 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(20 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           ^
                                                                                           c
                                                                                           ^
                                                                                           d).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(20
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(21 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(21 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(21 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(21 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(21 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           ^
                                                                                           b
                                                                                           ^
                                                                                           c).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(21
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(22 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(22 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(22 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(22 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(22 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           ^
                                                                                           a
                                                                                           ^
                                                                                           b).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(22
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(23 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(23 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(23 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(23 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(23 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           ^
                                                                                           e
                                                                                           ^
                                                                                           a).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(23
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(24 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(24 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(24 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(24 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(24 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           ^
                                                                                           d
                                                                                           ^
                                                                                           e).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(24
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(25 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(25 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(25 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(25 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(25 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           ^
                                                                                           c
                                                                                           ^
                                                                                           d).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(25
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(26 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(26 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(26 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(26 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(26 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           ^
                                                                                           b
                                                                                           ^
                                                                                           c).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(26
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(27 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(27 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(27 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(27 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(27 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           ^
                                                                                           a
                                                                                           ^
                                                                                           b).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(27
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(28 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(28 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(28 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(28 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(28 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           ^
                                                                                           e
                                                                                           ^
                                                                                           a).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(28
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(29 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(29 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(29 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(29 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(29 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           ^
                                                                                           d
                                                                                           ^
                                                                                           e).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(29
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(30 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(30 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(30 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(30 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(30 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           ^
                                                                                           c
                                                                                           ^
                                                                                           d).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(30
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(31 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(31 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(31 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(31 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(31 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           ^
                                                                                           b
                                                                                           ^
                                                                                           c).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(31
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(32 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(32 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(32 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(32 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(32 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           ^
                                                                                           a
                                                                                           ^
                                                                                           b).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(32
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(33 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(33 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(33 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(33 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(33 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           ^
                                                                                           e
                                                                                           ^
                                                                                           a).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(33
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(34 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(34 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(34 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(34 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(34 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           ^
                                                                                           d
                                                                                           ^
                                                                                           e).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(34
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(35 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(35 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(35 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(35 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(35 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           ^
                                                                                           c
                                                                                           ^
                                                                                           d).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(35
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(36 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(36 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(36 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(36 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(36 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           ^
                                                                                           b
                                                                                           ^
                                                                                           c).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(36
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(37 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(37 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(37 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(37 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(37 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           ^
                                                                                           a
                                                                                           ^
                                                                                           b).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(37
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(38 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(38 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(38 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(38 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(38 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           ^
                                                                                           e
                                                                                           ^
                                                                                           a).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(38
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(39 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(39 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(39 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(39 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(39 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           ^
                                                                                           d
                                                                                           ^
                                                                                           e).wrapping_add(0x6ed9eba1
                                                                                                               as
                                                                                                               libc::c_int
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(39
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(40 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(40 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(40 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(40 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(40 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           &
                                                                                           c
                                                                                           |
                                                                                           d
                                                                                               &
                                                                                               (b
                                                                                                    |
                                                                                                    c)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(40
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(41 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(41 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(41 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(41 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(41 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           &
                                                                                           b
                                                                                           |
                                                                                           c
                                                                                               &
                                                                                               (a
                                                                                                    |
                                                                                                    b)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(41
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(42 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(42 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(42 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(42 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(42 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           &
                                                                                           a
                                                                                           |
                                                                                           b
                                                                                               &
                                                                                               (e
                                                                                                    |
                                                                                                    a)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(42
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(43 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(43 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(43 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(43 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(43 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           &
                                                                                           e
                                                                                           |
                                                                                           a
                                                                                               &
                                                                                               (d
                                                                                                    |
                                                                                                    e)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(43
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(44 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(44 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(44 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(44 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(44 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           &
                                                                                           d
                                                                                           |
                                                                                           e
                                                                                               &
                                                                                               (c
                                                                                                    |
                                                                                                    d)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(44
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(45 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(45 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(45 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(45 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(45 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           &
                                                                                           c
                                                                                           |
                                                                                           d
                                                                                               &
                                                                                               (b
                                                                                                    |
                                                                                                    c)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(45
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(46 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(46 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(46 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(46 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(46 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           &
                                                                                           b
                                                                                           |
                                                                                           c
                                                                                               &
                                                                                               (a
                                                                                                    |
                                                                                                    b)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(46
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(47 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(47 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(47 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(47 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(47 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           &
                                                                                           a
                                                                                           |
                                                                                           b
                                                                                               &
                                                                                               (e
                                                                                                    |
                                                                                                    a)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(47
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(48 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(48 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(48 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(48 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(48 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           &
                                                                                           e
                                                                                           |
                                                                                           a
                                                                                               &
                                                                                               (d
                                                                                                    |
                                                                                                    e)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(48
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(49 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(49 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(49 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(49 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(49 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           &
                                                                                           d
                                                                                           |
                                                                                           e
                                                                                               &
                                                                                               (c
                                                                                                    |
                                                                                                    d)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(49
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(50 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(50 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(50 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(50 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(50 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           &
                                                                                           c
                                                                                           |
                                                                                           d
                                                                                               &
                                                                                               (b
                                                                                                    |
                                                                                                    c)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(50
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(51 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(51 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(51 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(51 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(51 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           &
                                                                                           b
                                                                                           |
                                                                                           c
                                                                                               &
                                                                                               (a
                                                                                                    |
                                                                                                    b)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(51
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(52 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(52 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(52 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(52 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(52 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           &
                                                                                           a
                                                                                           |
                                                                                           b
                                                                                               &
                                                                                               (e
                                                                                                    |
                                                                                                    a)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(52
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(53 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(53 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(53 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(53 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(53 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           &
                                                                                           e
                                                                                           |
                                                                                           a
                                                                                               &
                                                                                               (d
                                                                                                    |
                                                                                                    e)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(53
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(54 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(54 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(54 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(54 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(54 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           &
                                                                                           d
                                                                                           |
                                                                                           e
                                                                                               &
                                                                                               (c
                                                                                                    |
                                                                                                    d)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(54
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(55 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(55 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(55 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(55 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(55 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           &
                                                                                           c
                                                                                           |
                                                                                           d
                                                                                               &
                                                                                               (b
                                                                                                    |
                                                                                                    c)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(55
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(56 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(56 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(56 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(56 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(56 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           &
                                                                                           b
                                                                                           |
                                                                                           c
                                                                                               &
                                                                                               (a
                                                                                                    |
                                                                                                    b)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(56
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(57 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(57 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(57 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(57 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(57 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           &
                                                                                           a
                                                                                           |
                                                                                           b
                                                                                               &
                                                                                               (e
                                                                                                    |
                                                                                                    a)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(57
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(58 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(58 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(58 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(58 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(58 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           &
                                                                                           e
                                                                                           |
                                                                                           a
                                                                                               &
                                                                                               (d
                                                                                                    |
                                                                                                    e)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(58
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(59 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(59 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(59 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(59 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(59 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           &
                                                                                           d
                                                                                           |
                                                                                           e
                                                                                               &
                                                                                               (c
                                                                                                    |
                                                                                                    d)).wrapping_add(0x8f1bbcdc
                                                                                                                         as
                                                                                                                         libc::c_uint).wrapping_add(x[(59
                                                                                                                                                           as
                                                                                                                                                           libc::c_int
                                                                                                                                                           &
                                                                                                                                                           0xf
                                                                                                                                                               as
                                                                                                                                                               libc::c_int)
                                                                                                                                                          as
                                                                                                                                                          usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(60 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(60 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(60 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(60 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(60 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           ^
                                                                                           c
                                                                                           ^
                                                                                           d).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(60
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(61 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(61 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(61 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(61 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(61 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           ^
                                                                                           b
                                                                                           ^
                                                                                           c).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(61
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(62 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(62 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(62 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(62 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(62 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           ^
                                                                                           a
                                                                                           ^
                                                                                           b).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(62
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(63 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(63 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(63 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(63 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(63 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           ^
                                                                                           e
                                                                                           ^
                                                                                           a).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(63
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(64 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(64 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(64 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(64 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(64 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           ^
                                                                                           d
                                                                                           ^
                                                                                           e).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(64
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(65 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(65 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(65 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(65 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(65 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           ^
                                                                                           c
                                                                                           ^
                                                                                           d).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(65
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(66 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(66 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(66 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(66 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(66 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           ^
                                                                                           b
                                                                                           ^
                                                                                           c).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(66
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(67 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(67 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(67 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(67 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(67 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           ^
                                                                                           a
                                                                                           ^
                                                                                           b).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(67
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(68 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(68 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(68 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(68 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(68 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           ^
                                                                                           e
                                                                                           ^
                                                                                           a).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(68
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(69 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(69 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(69 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(69 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(69 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           ^
                                                                                           d
                                                                                           ^
                                                                                           e).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(69
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(70 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(70 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(70 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(70 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(70 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           ^
                                                                                           c
                                                                                           ^
                                                                                           d).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(70
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(71 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(71 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(71 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(71 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(71 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           ^
                                                                                           b
                                                                                           ^
                                                                                           c).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(71
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(72 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(72 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(72 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(72 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(72 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           ^
                                                                                           a
                                                                                           ^
                                                                                           b).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(72
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(73 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(73 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(73 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(73 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(73 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           ^
                                                                                           e
                                                                                           ^
                                                                                           a).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(73
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(74 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(74 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(74 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(74 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(74 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           ^
                                                                                           d
                                                                                           ^
                                                                                           e).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(74
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(75 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(75 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(75 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(75 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(75 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        e =
            (e as
                 libc::c_uint).wrapping_add((a << 5 as libc::c_int |
                                                 a >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(b
                                                                                           ^
                                                                                           c
                                                                                           ^
                                                                                           d).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(75
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        b =
            b << 30 as libc::c_int |
                b >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(76 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(76 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(76 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(76 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(76 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        d =
            (d as
                 libc::c_uint).wrapping_add((e << 5 as libc::c_int |
                                                 e >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(a
                                                                                           ^
                                                                                           b
                                                                                           ^
                                                                                           c).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(76
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        a =
            a << 30 as libc::c_int |
                a >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(77 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(77 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(77 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(77 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(77 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        c =
            (c as
                 libc::c_uint).wrapping_add((d << 5 as libc::c_int |
                                                 d >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(e
                                                                                           ^
                                                                                           a
                                                                                           ^
                                                                                           b).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(77
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        e =
            e << 30 as libc::c_int |
                e >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(78 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(78 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(78 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(78 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(78 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        b =
            (b as
                 libc::c_uint).wrapping_add((c << 5 as libc::c_int |
                                                 c >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(d
                                                                                           ^
                                                                                           e
                                                                                           ^
                                                                                           a).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(78
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        d =
            d << 30 as libc::c_int |
                d >> 32 as libc::c_int - 30 as libc::c_int;
        tm =
            x[(79 as libc::c_int & 0xf as libc::c_int) as usize] ^
                x[(79 as libc::c_int - 14 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(79 as libc::c_int - 8 as libc::c_int & 0xf as libc::c_int)
                      as usize] ^
                x[(79 as libc::c_int - 3 as libc::c_int & 0xf as libc::c_int)
                      as usize];
        x[(79 as libc::c_int & 0xf as libc::c_int) as usize] =
            tm << 1 as libc::c_int |
                tm >> 32 as libc::c_int - 1 as libc::c_int;
        a =
            (a as
                 libc::c_uint).wrapping_add((b << 5 as libc::c_int |
                                                 b >>
                                                     32 as libc::c_int -
                                                         5 as
                                                             libc::c_int).wrapping_add(c
                                                                                           ^
                                                                                           d
                                                                                           ^
                                                                                           e).wrapping_add(0xca62c1d6
                                                                                                               as
                                                                                                               libc::c_uint).wrapping_add(x[(79
                                                                                                                                                 as
                                                                                                                                                 libc::c_int
                                                                                                                                                 &
                                                                                                                                                 0xf
                                                                                                                                                     as
                                                                                                                                                     libc::c_int)
                                                                                                                                                as
                                                                                                                                                usize]))
                as uint32_t as uint32_t;
        c =
            c << 30 as libc::c_int |
                c >> 32 as libc::c_int - 30 as libc::c_int;
        (*ctx).A =
            ((*ctx).A as libc::c_uint).wrapping_add(a) as uint32_t as
                uint32_t;
        a = (*ctx).A;
        (*ctx).B =
            ((*ctx).B as libc::c_uint).wrapping_add(b) as uint32_t as
                uint32_t;
        b = (*ctx).B;
        (*ctx).C =
            ((*ctx).C as libc::c_uint).wrapping_add(c) as uint32_t as
                uint32_t;
        c = (*ctx).C;
        (*ctx).D =
            ((*ctx).D as libc::c_uint).wrapping_add(d) as uint32_t as
                uint32_t;
        d = (*ctx).D;
        (*ctx).E =
            ((*ctx).E as libc::c_uint).wrapping_add(e) as uint32_t as
                uint32_t;
        e = (*ctx).E
    };
}
/*
 * Hey Emacs!
 * Local Variables:
 * coding: utf-8
 * End:
 */
