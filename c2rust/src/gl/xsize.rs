use ::libc;
pub type size_t = libc::c_ulong;
/* xsize.h -- Checked size_t computations.

   Copyright (C) 2003, 2008-2021 Free Software Foundation, Inc.

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
/* Get size_t.  */
/* Get SIZE_MAX.  */
/* Get ATTRIBUTE_PURE.  */
/* The size of memory objects is often computed through expressions of
   type size_t. Example:
      void* p = malloc (header_size + n * element_size).
   These computations can lead to overflow.  When this happens, malloc()
   returns a piece of memory that is way too small, and the program then
   crashes while attempting to fill the memory.
   To avoid this, the functions and macros in this file check for overflow.
   The convention is that SIZE_MAX represents overflow.
   malloc (SIZE_MAX) is not guaranteed to fail -- think of a malloc
   implementation that uses mmap --, it's recommended to use size_overflow_p()
   or size_in_bounds_p() before invoking malloc().
   The example thus becomes:
      size_t size = xsum (header_size, xtimes (n, element_size));
      void *p = (size_in_bounds_p (size) ? malloc (size) : NULL);
*/
/* Convert an arbitrary value >= 0 to type size_t.  */
/* Sum of two sizes, with overflow check.  */
#[no_mangle]
#[inline]
pub unsafe extern "C" fn xsum(mut size1: size_t, mut size2: size_t)
 -> size_t {
    let mut sum: size_t = size1.wrapping_add(size2);
    return if sum >= size1 {
               sum
           } else { 18446744073709551615 as libc::c_ulong };
}
/* Sum of three sizes, with overflow check.  */
#[no_mangle]
#[inline]
pub unsafe extern "C" fn xsum3(mut size1: size_t, mut size2: size_t,
                               mut size3: size_t) -> size_t {
    return xsum(xsum(size1, size2), size3);
}
/* Sum of four sizes, with overflow check.  */
#[no_mangle]
#[inline]
pub unsafe extern "C" fn xsum4(mut size1: size_t, mut size2: size_t,
                               mut size3: size_t, mut size4: size_t)
 -> size_t {
    return xsum(xsum(xsum(size1, size2), size3), size4);
}
/* Maximum of two sizes, with overflow check.  */
#[no_mangle]
#[inline]
pub unsafe extern "C" fn xmax(mut size1: size_t, mut size2: size_t)
 -> size_t {
    /* No explicit check is needed here, because for any n:
     max (SIZE_MAX, n) == SIZE_MAX and max (n, SIZE_MAX) == SIZE_MAX.  */
    return if size1 >= size2 { size1 } else { size2 };
}
/* Checked size_t computations.

   Copyright (C) 2012-2021 Free Software Foundation, Inc.

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
