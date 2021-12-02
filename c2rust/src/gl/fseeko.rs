use ::libc;
extern "C" {
    #[no_mangle]
    fn fseeko(__stream: *mut FILE, __off: __off_t, __whence: libc::c_int)
     -> libc::c_int;
    #[no_mangle]
    fn fileno(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn lseek(__fd: libc::c_int, __offset: __off_t, __whence: libc::c_int)
     -> __off_t;
}
pub type size_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
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
pub type off_t = __off_t;
/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* A GNU-like <stdio.h>.

   Copyright (C) 2004, 2007-2021 Free Software Foundation, Inc.

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
/* An fseeko() function that, together with fflush(), is POSIX compliant.
   Copyright (C) 2007-2021 Free Software Foundation, Inc.

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
/* Specification.  */
/* Get off_t, lseek, _POSIX_VERSION.  */
#[no_mangle]
pub unsafe extern "C" fn rpl_fseeko(mut fp: *mut FILE, mut offset: off_t,
                                    mut whence: libc::c_int) -> libc::c_int {
    /* These tests are based on fpurge.c.  */
    /* GNU libc, BeOS, Haiku, Linux libc5 */
    if (*fp)._IO_read_end == (*fp)._IO_read_ptr &&
           (*fp)._IO_write_ptr == (*fp)._IO_write_base &&
           (*fp)._IO_save_base.is_null() {
        /* We get here when an fflush() call immediately preceded this one (or
         if ftell() has created buffers but no I/O has occurred on a
         newly-opened stream).  We know there are no buffers.  */
        let mut pos: off_t = lseek(fileno(fp), offset, whence);
        if pos == -(1 as libc::c_int) as libc::c_long {
            return -(1 as libc::c_int)
        }
        /* GNU libc, BeOS, Haiku, Linux libc5 */
        (*fp)._flags &= !(0x10 as libc::c_int);
        (*fp)._offset = pos;
        return 0 as libc::c_int
    }
    return fseeko(fp, offset, whence);
}
