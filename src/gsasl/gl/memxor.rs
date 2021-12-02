use ::libc;
pub type size_t = libc::c_ulong;
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
/* Binary exclusive OR operation of two memory blocks.  -*- coding: utf-8 -*-
   Copyright (C) 2005-2006, 2009-2021 Free Software Foundation, Inc.

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
#[no_mangle]
pub unsafe extern "C" fn memxor(mut dest: *mut libc::c_void,
                                mut src: *const libc::c_void, mut n: size_t)
 -> *mut libc::c_void {
    let mut s: *const libc::c_char = src as *const libc::c_char;
    let mut d: *mut libc::c_char = dest as *mut libc::c_char;
    while n > 0 as libc::c_int as libc::c_ulong {
        let fresh0 = s;
        s = s.offset(1);
        let fresh1 = d;
        d = d.offset(1);
        *fresh1 =
            (*fresh1 as libc::c_int ^ *fresh0 as libc::c_int) as libc::c_char;
        n = n.wrapping_sub(1)
    }
    return dest;
}
