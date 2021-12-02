use ::libc;
extern "C" {
    #[no_mangle]
    fn md5_finish_ctx(ctx: *mut md5_ctx, resbuf: *mut libc::c_void)
     -> *mut libc::c_void;
    #[no_mangle]
    fn md5_process_bytes(buffer: *const libc::c_void, len: size_t,
                         ctx: *mut md5_ctx);
    #[no_mangle]
    fn md5_process_block(buffer: *const libc::c_void, len: size_t,
                         ctx: *mut md5_ctx);
    #[no_mangle]
    fn md5_init_ctx(ctx: *mut md5_ctx);
    #[no_mangle]
    fn fread(_: *mut libc::c_void, _: libc::c_ulong, _: libc::c_ulong,
             _: *mut FILE) -> libc::c_ulong;
    #[no_mangle]
    fn feof(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn ferror(__stream: *mut FILE) -> libc::c_int;
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
    #[no_mangle]
    fn rpl_free(ptr: *mut libc::c_void);
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __ssize_t = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub __pad1: *mut libc::c_void,
    pub __pad2: *mut libc::c_void,
    pub __pad3: *mut libc::c_void,
    pub __pad4: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_marker {
    pub _next: *mut _IO_marker,
    pub _sbuf: *mut _IO_FILE,
    pub _pos: libc::c_int,
}
pub type FILE = _IO_FILE;
pub type ssize_t = __ssize_t;
pub type uint32_t = __uint32_t;
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
/* af_alg.h - Compute message digests from file streams and buffers.
   Copyright (C) 2018-2021 Free Software Foundation, Inc.

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
/* Written by Matteo Croce <mcroce@redhat.com>, 2018.
   Documentation by Bruno Haible <bruno@clisp.org>, 2018.  */
/* Declare specific functions for computing message digests
   using the Linux kernel crypto API, if available.  This kernel API gives
   access to specialized crypto instructions (that would also be available
   in user space) or to crypto devices (not directly available in user space).

   For a more complete set of facilities that use the Linux kernel crypto API,
   look at libkcapi.  */
#[inline]
unsafe extern "C" fn afalg_stream(mut stream: *mut FILE,
                                  mut alg: *const libc::c_char,
                                  mut resblock: *mut libc::c_void,
                                  mut hashlen: ssize_t) -> libc::c_int {
    return -(97 as libc::c_int);
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
/* ≥ 0, ≤ 128 */
/* 128 bytes; the first buflen bytes are in use */
/*
 * The following three functions are build up the low level used in
 * the functions 'md5_stream' and 'md5_buffer'.
 */
/* Initialize structure containing state of computation.
   (RFC 1321, 3.3: Step 3)  */
/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is necessary that LEN is a multiple of 64!!! */
/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is NOT required that LEN is a multiple of 64.  */
/* Process the remaining bytes in the buffer and put result from CTX
   in first 16 bytes following RESBUF.  The result is always in little
   endian byte order, so that a byte-wise output yields to the wanted
   ASCII representation of the message digest.  */
/* Put result from CTX in first 16 bytes following RESBUF.  The result is
   always in little endian byte order, so that a byte-wise output yields
   to the wanted ASCII representation of the message digest.  */
/* Compute MD5 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
/* Compute MD5 message digest for bytes read from STREAM.
   STREAM is an open file stream.  Regular files are handled more efficiently.
   The contents of STREAM from its current position to its end will be read.
   The case that the last operation on STREAM was an 'ungetc' is not supported.
   The resulting message digest number will be written into the 16 bytes
   beginning at RESBLOCK.  */
/* Compute MD5 message digest for bytes read from STREAM.  The
   resulting message digest number will be written into the 16 bytes
   beginning at RESBLOCK.  */
#[no_mangle]
pub unsafe extern "C" fn md5_stream(mut stream: *mut FILE,
                                    mut resblock: *mut libc::c_void)
 -> libc::c_int {
    match afalg_stream(stream, b"md5\x00" as *const u8 as *const libc::c_char,
                       resblock, 16 as libc::c_int as ssize_t) {
        0 => { return 0 as libc::c_int }
        -5 => { return 1 as libc::c_int }
        _ => { }
    }
    let mut buffer: *mut libc::c_char =
        malloc((32768 as libc::c_int + 72 as libc::c_int) as libc::c_ulong) as
            *mut libc::c_char;
    if buffer.is_null() { return 1 as libc::c_int }
    let mut ctx: md5_ctx =
        md5_ctx{A: 0,
                B: 0,
                C: 0,
                D: 0,
                total: [0; 2],
                buflen: 0,
                buffer: [0; 32],};
    md5_init_ctx(&mut ctx);
    let mut sum: size_t = 0;
    /* Iterate over full file contents.  */
    's_42:
        loop 
             /* We read the file in blocks of BLOCKSIZE bytes.  One call of the
         computation function processes the whole buffer so that with the
         next round of the loop another block can be read.  */
             {
            let mut n: size_t = 0;
            sum = 0 as libc::c_int as size_t;
            /* Read block.  Take care for partial reads.  */
            loop 
                 /* Either process a partial fread() from this loop,
             or the fread() in afalg_stream may have gotten EOF.
             We need to avoid a subsequent fread() as EOF may
             not be sticky.  For details of such systems, see:
             https://sourceware.org/bugzilla/show_bug.cgi?id=1190  */
                 {
                if feof(stream) != 0 { break 's_42 ; }
                n =
                    fread(buffer.offset(sum as isize) as *mut libc::c_void,
                          1 as libc::c_int as libc::c_ulong,
                          (32768 as libc::c_int as
                               libc::c_ulong).wrapping_sub(sum), stream);
                sum =
                    (sum as libc::c_ulong).wrapping_add(n) as size_t as
                        size_t;
                if sum == 32768 as libc::c_int as libc::c_ulong { break ; }
                if !(n == 0 as libc::c_int as libc::c_ulong) { continue ; }
                /* Check for the error flag IFF N == 0, so that we don't
                 exit the loop after a partial read due to e.g., EAGAIN
                 or EWOULDBLOCK.  */
                if ferror(stream) != 0 {
                    rpl_free(buffer as *mut libc::c_void);
                    return 1 as libc::c_int
                }
                break 's_42 ;
            }
            /* Process buffer with BLOCKSIZE bytes.  Note that
         BLOCKSIZE % 64 == 0
       */
            md5_process_block(buffer as *const libc::c_void,
                              32768 as libc::c_int as size_t, &mut ctx);
        }
    /* Process any remaining bytes.  */
    if sum > 0 as libc::c_int as libc::c_ulong {
        md5_process_bytes(buffer as *const libc::c_void, sum, &mut ctx);
    }
    /* Construct result in desired memory.  */
    md5_finish_ctx(&mut ctx, resblock);
    rpl_free(buffer as *mut libc::c_void);
    return 0 as libc::c_int;
}
/*
 * Hey Emacs!
 * Local Variables:
 * coding: utf-8
 * End:
 */
