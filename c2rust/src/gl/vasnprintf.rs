use ::libc;
extern "C" {
    #[no_mangle]
    fn snprintf(_: *mut libc::c_char, _: libc::c_ulong,
                _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn abort() -> !;
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
    #[no_mangle]
    fn rpl_free(ptr: *mut libc::c_void);
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn __errno_location() -> *mut libc::c_int;
    /* Fetch the arguments, putting them into a. */
    #[no_mangle]
    fn printf_fetchargs(args: ::std::ffi::VaList, a: *mut arguments)
     -> libc::c_int;
    /* Parses the format string.  Fills in the number N of directives, and fills
   in directives[0], ..., directives[N-1], and sets directives[N].dir_start
   to the end of the format string.  Also fills in the arg_type fields of the
   arguments and the needed count of arguments.  */
    #[no_mangle]
    fn printf_parse(format: *const libc::c_char, d: *mut char_directives,
                    a: *mut arguments) -> libc::c_int;
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type size_t = libc::c_ulong;
pub type wchar_t = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct argument {
    pub type_0: arg_type,
    pub a: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub a_schar: libc::c_schar,
    pub a_uchar: libc::c_uchar,
    pub a_short: libc::c_short,
    pub a_ushort: libc::c_ushort,
    pub a_int: libc::c_int,
    pub a_uint: libc::c_uint,
    pub a_longint: libc::c_long,
    pub a_ulongint: libc::c_ulong,
    pub a_longlongint: libc::c_longlong,
    pub a_ulonglongint: libc::c_ulonglong,
    pub a_float: libc::c_float,
    pub a_double: libc::c_double,
    pub a_char: libc::c_int,
    pub a_wide_char: wint_t,
    pub a_string: *const libc::c_char,
    pub a_wide_string: *const wchar_t,
    pub a_pointer: *mut libc::c_void,
    pub a_count_schar_pointer: *mut libc::c_schar,
    pub a_count_short_pointer: *mut libc::c_short,
    pub a_count_int_pointer: *mut libc::c_int,
    pub a_count_longint_pointer: *mut libc::c_long,
    pub a_count_longlongint_pointer: *mut libc::c_longlong,
}
pub type wint_t = libc::c_uint;
pub type arg_type = libc::c_uint;
pub const TYPE_COUNT_LONGLONGINT_POINTER: arg_type = 22;
pub const TYPE_COUNT_LONGINT_POINTER: arg_type = 21;
pub const TYPE_COUNT_INT_POINTER: arg_type = 20;
pub const TYPE_COUNT_SHORT_POINTER: arg_type = 19;
pub const TYPE_COUNT_SCHAR_POINTER: arg_type = 18;
pub const TYPE_POINTER: arg_type = 17;
pub const TYPE_WIDE_STRING: arg_type = 16;
pub const TYPE_STRING: arg_type = 15;
pub const TYPE_WIDE_CHAR: arg_type = 14;
pub const TYPE_CHAR: arg_type = 13;
pub const TYPE_LONGDOUBLE: arg_type = 12;
pub const TYPE_DOUBLE: arg_type = 11;
pub const TYPE_ULONGLONGINT: arg_type = 10;
pub const TYPE_LONGLONGINT: arg_type = 9;
pub const TYPE_ULONGINT: arg_type = 8;
pub const TYPE_LONGINT: arg_type = 7;
pub const TYPE_UINT: arg_type = 6;
pub const TYPE_INT: arg_type = 5;
pub const TYPE_USHORT: arg_type = 4;
pub const TYPE_SHORT: arg_type = 3;
pub const TYPE_UCHAR: arg_type = 2;
pub const TYPE_SCHAR: arg_type = 1;
pub const TYPE_NONE: arg_type = 0;
/* Decomposed printf argument list.
   Copyright (C) 1999, 2002-2003, 2006-2007, 2011-2021 Free Software
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
/* This file can be parametrized with the following macros:
     ENABLE_UNISTDIO    Set to 1 to enable the unistdio extensions.
     PRINTF_FETCHARGS   Name of the function to be declared.
     STATIC             Set to 'static' to declare the function static.  */
/* Default parameters.  */
/* Get size_t.  */
/* Get wchar_t.  */
/* Get wint_t.  */
/* Get va_list.  */
/* Argument types */
/* Polymorphic argument */
/* Number of directly allocated arguments (no malloc() needed).  */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct arguments {
    pub count: size_t,
    pub arg: *mut argument,
    pub direct_alloc_arg: [argument; 7],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct char_directive {
    pub dir_start: *const libc::c_char,
    pub dir_end: *const libc::c_char,
    pub flags: libc::c_int,
    pub width_start: *const libc::c_char,
    pub width_end: *const libc::c_char,
    pub width_arg_index: size_t,
    pub precision_start: *const libc::c_char,
    pub precision_end: *const libc::c_char,
    pub precision_arg_index: size_t,
    pub conversion: libc::c_char,
    pub arg_index: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct char_directives {
    pub count: size_t,
    pub dir: *mut char_directive,
    pub max_width_length: size_t,
    pub max_precision_length: size_t,
    pub direct_alloc_dir: [char_directive; 7],
}
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
/* Sum of three sizes, with overflow check.  */
/* Sum of four sizes, with overflow check.  */
#[inline]
unsafe extern "C" fn xsum4(mut size1: size_t, mut size2: size_t,
                           mut size3: size_t, mut size4: size_t) -> size_t {
    return xsum(xsum(xsum(size1, size2), size3), size4);
}
/* Maximum of two sizes, with overflow check.  */
#[inline]
unsafe extern "C" fn xmax(mut size1: size_t, mut size2: size_t) -> size_t {
    /* No explicit check is needed here, because for any n:
     max (SIZE_MAX, n) == SIZE_MAX and max (n, SIZE_MAX) == SIZE_MAX.  */
    return if size1 >= size2 { size1 } else { size2 };
}
#[inline]
unsafe extern "C" fn xsum(mut size1: size_t, mut size2: size_t) -> size_t {
    let mut sum: size_t = size1.wrapping_add(size2);
    return if sum >= size1 {
               sum
           } else { 18446744073709551615 as libc::c_ulong };
}
/* vsprintf with automatic memory allocation.
   Copyright (C) 2002-2004, 2007-2021 Free Software Foundation, Inc.

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
/* Get va_list.  */
/* Get size_t.  */
/* Get _GL_ATTRIBUTE_SPEC_PRINTF_STANDARD.  */
/* Write formatted output to a string dynamically allocated with malloc().
   You can pass a preallocated buffer for the result in RESULTBUF and its
   size in *LENGTHP; otherwise you pass RESULTBUF = NULL.
   If successful, return the address of the string (this may be = RESULTBUF
   if no dynamic memory allocation was necessary) and set *LENGTHP to the
   number of resulting bytes, excluding the trailing NUL.  Upon error, set
   errno and return NULL.

   When dynamic memory allocation occurs, the preallocated buffer is left
   alone (with possibly modified contents).  This makes it possible to use
   a statically allocated or stack-allocated buffer, like this:

          char buf[100];
          size_t len = sizeof (buf);
          char *output = vasnprintf (buf, &len, format, args);
          if (output == NULL)
            ... error handling ...;
          else
            {
              ... use the output string ...;
              if (output != buf)
                free (output);
            }
  */
/* Here we need to call the native snprintf, not rpl_snprintf.  */
/* Here we need to call the native sprintf, not rpl_sprintf.  */
/* GCC >= 4.0 with -Wall emits unjustified "... may be used uninitialized"
   warnings in this file.  Use -Dlint to suppress them.  */
/* empty */
/* Avoid some warnings from "gcc -Wshadow".
   This file doesn't use the exp() and remainder() functions.  */
#[no_mangle]
pub unsafe extern "C" fn vasnprintf(mut resultbuf: *mut libc::c_char,
                                    mut lengthp: *mut size_t,
                                    mut format: *const libc::c_char,
                                    mut args: ::std::ffi::VaList)
 -> *mut libc::c_char {
    let mut current_block: u64;
    let mut d: char_directives =
        char_directives{count: 0,
                        dir: 0 as *mut char_directive,
                        max_width_length: 0,
                        max_precision_length: 0,
                        direct_alloc_dir:
                            [char_directive{dir_start:
                                                0 as *const libc::c_char,
                                            dir_end: 0 as *const libc::c_char,
                                            flags: 0,
                                            width_start:
                                                0 as *const libc::c_char,
                                            width_end:
                                                0 as *const libc::c_char,
                                            width_arg_index: 0,
                                            precision_start:
                                                0 as *const libc::c_char,
                                            precision_end:
                                                0 as *const libc::c_char,
                                            precision_arg_index: 0,
                                            conversion: 0,
                                            arg_index: 0,}; 7],};
    let mut a: arguments =
        arguments{count: 0,
                  arg: 0 as *mut argument,
                  direct_alloc_arg:
                      [argument{type_0: TYPE_NONE,
                                a: C2RustUnnamed{a_schar: 0,},}; 7],};
    if printf_parse(format, &mut d, &mut a) < 0 as libc::c_int {
        /* errno is already set.  */
        return 0 as *mut libc::c_char
    }
    /* Frees the memory allocated by this function.  Preserves errno.  */
    if printf_fetchargs(args.as_va_list(), &mut a) < 0 as libc::c_int {
        if d.dir != d.direct_alloc_dir.as_mut_ptr() {
            rpl_free(d.dir as *mut libc::c_void);
        }
        if a.arg != a.direct_alloc_arg.as_mut_ptr() {
            rpl_free(a.arg as *mut libc::c_void);
        }
        *__errno_location() = 22 as libc::c_int;
        return 0 as *mut libc::c_char
    }
    let mut buf_neededlength: size_t = 0;
    let mut buf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut buf_malloced: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *const libc::c_char = 0 as *const libc::c_char;
    let mut i: size_t = 0;
    let mut dp: *mut char_directive = 0 as *mut char_directive;
    /* Output string accumulator.  */
    let mut result: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut allocated: size_t = 0;
    let mut length: size_t = 0;
    /* Allocate a small buffer that will hold a directive passed to
       sprintf or snprintf.  */
    buf_neededlength =
        xsum4(7 as libc::c_int as size_t, d.max_width_length,
              d.max_precision_length, 6 as libc::c_int as size_t);
    if buf_neededlength <
           (4000 as libc::c_int as
                libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                as libc::c_ulong) {
        let mut fresh0 =
            ::std::vec::from_elem(0,
                                  buf_neededlength.wrapping_mul(::std::mem::size_of::<libc::c_char>()
                                                                    as
                                                                    libc::c_ulong)
                                      as usize);
        buf = fresh0.as_mut_ptr() as *mut libc::c_char;
        buf_malloced = 0 as *mut libc::c_char;
        current_block = 7172762164747879670;
    } else {
        let mut buf_memsize: size_t =
            if buf_neededlength <=
                   (18446744073709551615 as
                        libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                        as libc::c_ulong) {
                buf_neededlength.wrapping_mul(::std::mem::size_of::<libc::c_char>()
                                                  as libc::c_ulong)
            } else { 18446744073709551615 as libc::c_ulong };
        if buf_memsize == 18446744073709551615 as libc::c_ulong {
            current_block = 16801907644790847396;
        } else {
            buf = malloc(buf_memsize) as *mut libc::c_char;
            if buf.is_null() {
                current_block = 16801907644790847396;
            } else {
                buf_malloced = buf;
                current_block = 7172762164747879670;
            }
        }
    }
    match current_block {
        7172762164747879670 => {
            if !resultbuf.is_null() {
                result = resultbuf;
                allocated = *lengthp
            } else {
                result = 0 as *mut libc::c_char;
                allocated = 0 as libc::c_int as size_t
            }
            length = 0 as libc::c_int as size_t;
            /* Invariants:
       result is either == resultbuf or == NULL or malloc-allocated.
       If length > 0, then result != NULL.  */
            /* Ensures that allocated >= needed.  Aborts through a jump to
       out_of_memory if needed is SIZE_MAX or otherwise too big.  */
            cp = format;
            i = 0 as libc::c_int as size_t;
            dp =
                &mut *d.dir.offset(0 as libc::c_int as isize) as
                    *mut char_directive;
            's_174:
                loop  {
                    if cp != (*dp).dir_start {
                        let mut n: size_t =
                            (*dp).dir_start.wrapping_offset_from(cp) as
                                libc::c_long as size_t;
                        let mut augmented_length: size_t = xsum(length, n);
                        if augmented_length > allocated {
                            let mut memory_size: size_t = 0;
                            let mut memory: *mut libc::c_char =
                                0 as *mut libc::c_char;
                            allocated =
                                if allocated >
                                       0 as libc::c_int as libc::c_ulong {
                                    if allocated <=
                                           (18446744073709551615 as
                                                libc::c_ulong).wrapping_div(2
                                                                                as
                                                                                libc::c_int
                                                                                as
                                                                                libc::c_ulong)
                                       {
                                        allocated.wrapping_mul(2 as
                                                                   libc::c_int
                                                                   as
                                                                   libc::c_ulong)
                                    } else {
                                        18446744073709551615 as libc::c_ulong
                                    }
                                } else { 12 as libc::c_int as libc::c_ulong };
                            if augmented_length > allocated {
                                allocated = augmented_length
                            }
                            memory_size =
                                if allocated <=
                                       (18446744073709551615 as
                                            libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                            as
                                                                            libc::c_ulong)
                                   {
                                    allocated.wrapping_mul(::std::mem::size_of::<libc::c_char>()
                                                               as
                                                               libc::c_ulong)
                                } else {
                                    18446744073709551615 as libc::c_ulong
                                };
                            if memory_size ==
                                   18446744073709551615 as libc::c_ulong {
                                current_block = 3630591880094558253;
                                break ;
                            }
                            if result == resultbuf || result.is_null() {
                                memory =
                                    malloc(memory_size) as *mut libc::c_char
                            } else {
                                memory =
                                    realloc(result as *mut libc::c_void,
                                            memory_size) as *mut libc::c_char
                            }
                            if memory.is_null() {
                                current_block = 3630591880094558253;
                                break ;
                            }
                            if result == resultbuf &&
                                   length > 0 as libc::c_int as libc::c_ulong
                               {
                                memcpy(memory as *mut libc::c_void,
                                       result as *const libc::c_void, length);
                            }
                            result = memory
                        }
                        /* This copies a piece of FCHAR_T[] into a DCHAR_T[].  Here we
               need that the format string contains only ASCII characters
               if FCHAR_T and DCHAR_T are not the same type.  */
                        if ::std::mem::size_of::<libc::c_char>() as
                               libc::c_ulong ==
                               ::std::mem::size_of::<libc::c_char>() as
                                   libc::c_ulong {
                            memcpy(result.offset(length as isize) as
                                       *mut libc::c_void,
                                   cp as *const libc::c_void, n);
                            length = augmented_length
                        } else {
                            loop  {
                                let fresh1 = cp;
                                cp = cp.offset(1);
                                let fresh2 = length;
                                length = length.wrapping_add(1);
                                *result.offset(fresh2 as isize) = *fresh1;
                                n = n.wrapping_sub(1);
                                if !(n > 0 as libc::c_int as libc::c_ulong) {
                                    break ;
                                }
                            }
                        }
                    }
                    if i == d.count {
                        current_block = 14540000294252553875;
                        break ;
                    }
                    /* Execute a single directive.  */
                    if (*dp).conversion as libc::c_int == '%' as i32 {
                        let mut augmented_length_0: size_t = 0;
                        if !((*dp).arg_index == !(0 as libc::c_int as size_t))
                           {
                            abort();
                        }
                        augmented_length_0 =
                            xsum(length, 1 as libc::c_int as size_t);
                        if augmented_length_0 > allocated {
                            let mut memory_size_0: size_t = 0;
                            let mut memory_0: *mut libc::c_char =
                                0 as *mut libc::c_char;
                            allocated =
                                if allocated >
                                       0 as libc::c_int as libc::c_ulong {
                                    if allocated <=
                                           (18446744073709551615 as
                                                libc::c_ulong).wrapping_div(2
                                                                                as
                                                                                libc::c_int
                                                                                as
                                                                                libc::c_ulong)
                                       {
                                        allocated.wrapping_mul(2 as
                                                                   libc::c_int
                                                                   as
                                                                   libc::c_ulong)
                                    } else {
                                        18446744073709551615 as libc::c_ulong
                                    }
                                } else { 12 as libc::c_int as libc::c_ulong };
                            if augmented_length_0 > allocated {
                                allocated = augmented_length_0
                            }
                            memory_size_0 =
                                if allocated <=
                                       (18446744073709551615 as
                                            libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                            as
                                                                            libc::c_ulong)
                                   {
                                    allocated.wrapping_mul(::std::mem::size_of::<libc::c_char>()
                                                               as
                                                               libc::c_ulong)
                                } else {
                                    18446744073709551615 as libc::c_ulong
                                };
                            if memory_size_0 ==
                                   18446744073709551615 as libc::c_ulong {
                                current_block = 3630591880094558253;
                                break ;
                            }
                            if result == resultbuf || result.is_null() {
                                memory_0 =
                                    malloc(memory_size_0) as *mut libc::c_char
                            } else {
                                memory_0 =
                                    realloc(result as *mut libc::c_void,
                                            memory_size_0) as
                                        *mut libc::c_char
                            }
                            if memory_0.is_null() {
                                current_block = 3630591880094558253;
                                break ;
                            }
                            if result == resultbuf &&
                                   length > 0 as libc::c_int as libc::c_ulong
                               {
                                memcpy(memory_0 as *mut libc::c_void,
                                       result as *const libc::c_void, length);
                            }
                            result = memory_0
                        }
                        *result.offset(length as isize) =
                            '%' as i32 as libc::c_char;
                        length = augmented_length_0
                    } else {
                        if !((*dp).arg_index != !(0 as libc::c_int as size_t))
                           {
                            abort();
                        }
                        if (*dp).conversion as libc::c_int == 'n' as i32 {
                            match (*a.arg.offset((*dp).arg_index as
                                                     isize)).type_0 as
                                      libc::c_uint {
                                18 => {
                                    *(*a.arg.offset((*dp).arg_index as
                                                        isize)).a.a_count_schar_pointer
                                        = length as libc::c_schar
                                }
                                19 => {
                                    *(*a.arg.offset((*dp).arg_index as
                                                        isize)).a.a_count_short_pointer
                                        = length as libc::c_short
                                }
                                20 => {
                                    *(*a.arg.offset((*dp).arg_index as
                                                        isize)).a.a_count_int_pointer
                                        = length as libc::c_int
                                }
                                21 => {
                                    *(*a.arg.offset((*dp).arg_index as
                                                        isize)).a.a_count_longint_pointer
                                        = length as libc::c_long
                                }
                                22 => {
                                    *(*a.arg.offset((*dp).arg_index as
                                                        isize)).a.a_count_longlongint_pointer
                                        = length as libc::c_longlong
                                }
                                _ => { abort(); }
                            }
                        } else {
                            let mut type_0: arg_type =
                                (*a.arg.offset((*dp).arg_index as
                                                   isize)).type_0;
                            let mut flags: libc::c_int = (*dp).flags;
                            let mut fbp: *mut libc::c_char =
                                0 as *mut libc::c_char;
                            let mut prefix_count: libc::c_uint = 0;
                            let mut prefixes: [libc::c_int; 2] = [0; 2];
                            let mut orig_errno: libc::c_int = 0;
                            /* Decide whether to handle the precision ourselves.  */
                            /* Decide whether to perform the padding ourselves.  */
                            /* Construct the format string for calling snprintf or
                   sprintf.  */
                            fbp = buf;
                            let fresh3 = fbp;
                            fbp = fbp.offset(1);
                            *fresh3 = '%' as i32 as libc::c_char;
                            if flags & 1 as libc::c_int != 0 {
                                let fresh4 = fbp;
                                fbp = fbp.offset(1);
                                *fresh4 = '\'' as i32 as libc::c_char
                            }
                            if flags & 2 as libc::c_int != 0 {
                                let fresh5 = fbp;
                                fbp = fbp.offset(1);
                                *fresh5 = '-' as i32 as libc::c_char
                            }
                            if flags & 4 as libc::c_int != 0 {
                                let fresh6 = fbp;
                                fbp = fbp.offset(1);
                                *fresh6 = '+' as i32 as libc::c_char
                            }
                            if flags & 8 as libc::c_int != 0 {
                                let fresh7 = fbp;
                                fbp = fbp.offset(1);
                                *fresh7 = ' ' as i32 as libc::c_char
                            }
                            if flags & 16 as libc::c_int != 0 {
                                let fresh8 = fbp;
                                fbp = fbp.offset(1);
                                *fresh8 = '#' as i32 as libc::c_char
                            }
                            if flags & 64 as libc::c_int != 0 {
                                let fresh9 = fbp;
                                fbp = fbp.offset(1);
                                *fresh9 = 'I' as i32 as libc::c_char
                            }
                            if 0 as libc::c_int == 0 {
                                if flags & 32 as libc::c_int != 0 {
                                    let fresh10 = fbp;
                                    fbp = fbp.offset(1);
                                    *fresh10 = '0' as i32 as libc::c_char
                                }
                                if (*dp).width_start != (*dp).width_end {
                                    let mut n_0: size_t =
                                        (*dp).width_end.wrapping_offset_from((*dp).width_start)
                                            as libc::c_long as size_t;
                                    /* The width specification is known to consist only
                           of standard ASCII characters.  */
                                    if ::std::mem::size_of::<libc::c_char>()
                                           as libc::c_ulong ==
                                           ::std::mem::size_of::<libc::c_char>()
                                               as libc::c_ulong {
                                        memcpy(fbp as *mut libc::c_void,
                                               (*dp).width_start as
                                                   *const libc::c_void,
                                               n_0.wrapping_mul(::std::mem::size_of::<libc::c_char>()
                                                                    as
                                                                    libc::c_ulong));
                                        fbp = fbp.offset(n_0 as isize)
                                    } else {
                                        let mut mp: *const libc::c_char =
                                            (*dp).width_start;
                                        loop  {
                                            let fresh11 = mp;
                                            mp = mp.offset(1);
                                            let fresh12 = fbp;
                                            fbp = fbp.offset(1);
                                            *fresh12 = *fresh11;
                                            n_0 = n_0.wrapping_sub(1);
                                            if !(n_0 >
                                                     0 as libc::c_int as
                                                         libc::c_ulong) {
                                                break ;
                                            }
                                        }
                                    }
                                }
                            }
                            if 0 as libc::c_int == 0 {
                                if (*dp).precision_start !=
                                       (*dp).precision_end {
                                    let mut n_1: size_t =
                                        (*dp).precision_end.wrapping_offset_from((*dp).precision_start)
                                            as libc::c_long as size_t;
                                    /* The precision specification is known to consist only
                           of standard ASCII characters.  */
                                    if ::std::mem::size_of::<libc::c_char>()
                                           as libc::c_ulong ==
                                           ::std::mem::size_of::<libc::c_char>()
                                               as libc::c_ulong {
                                        memcpy(fbp as *mut libc::c_void,
                                               (*dp).precision_start as
                                                   *const libc::c_void,
                                               n_1.wrapping_mul(::std::mem::size_of::<libc::c_char>()
                                                                    as
                                                                    libc::c_ulong));
                                        fbp = fbp.offset(n_1 as isize)
                                    } else {
                                        let mut mp_0: *const libc::c_char =
                                            (*dp).precision_start;
                                        loop  {
                                            let fresh13 = mp_0;
                                            mp_0 = mp_0.offset(1);
                                            let fresh14 = fbp;
                                            fbp = fbp.offset(1);
                                            *fresh14 = *fresh13;
                                            n_1 = n_1.wrapping_sub(1);
                                            if !(n_1 >
                                                     0 as libc::c_int as
                                                         libc::c_ulong) {
                                                break ;
                                            }
                                        }
                                    }
                                }
                            }
                            let mut current_block_111: u64;
                            match type_0 as libc::c_uint {
                                9 | 10 => {
                                    let fresh15 = fbp;
                                    fbp = fbp.offset(1);
                                    *fresh15 = 'l' as i32 as libc::c_char;
                                    current_block_111 = 11474644750452698476;
                                }
                                7 | 8 | 14 | 16 => {
                                    current_block_111 = 11474644750452698476;
                                }
                                12 => {
                                    let fresh17 = fbp;
                                    fbp = fbp.offset(1);
                                    *fresh17 = 'L' as i32 as libc::c_char;
                                    current_block_111 = 9255187738567101705;
                                }
                                _ => {
                                    current_block_111 = 9255187738567101705;
                                }
                            }
                            match current_block_111 {
                                11474644750452698476 => {
                                    let fresh16 = fbp;
                                    fbp = fbp.offset(1);
                                    *fresh16 = 'l' as i32 as libc::c_char
                                }
                                _ => { }
                            }
                            *fbp = (*dp).conversion;
                            /* On systems where we know that snprintf's return value
                   conforms to ISO C 99 (HAVE_SNPRINTF_RETVAL_C99) and that
                   snprintf always produces NUL-terminated strings
                   (HAVE_SNPRINTF_TRUNCATION_C99), it is possible to avoid
                   using %n.  And it is desirable to do so, because more and
                   more platforms no longer support %n, for "security reasons".
                   In particular, the following platforms:
                     - On glibc2 systems from 2004-10-18 or newer, the use of
                       %n in format strings in writable memory may crash the
                       program (if compiled with _FORTIFY_SOURCE=2).
                     - On Mac OS X 10.13 or newer, the use of %n in format
                       strings in writable memory by default crashes the
                       program.
                     - On Android, starting on 2018-03-07, the use of %n in
                       format strings produces a fatal error (see
                       <https://android.googlesource.com/platform/bionic/+/41398d03b7e8e0dfb951660ae713e682e9fc0336>).
                   On these platforms, HAVE_SNPRINTF_RETVAL_C99 and
                   HAVE_SNPRINTF_TRUNCATION_C99 are 1. We have listed them
                   explicitly in the condition above, in case of cross-
                   compilation (just to be sure).  */
                /* On native Windows systems (such as mingw), we can avoid using
                   %n because:
                     - Although the gl_SNPRINTF_TRUNCATION_C99 test fails,
                       snprintf does not write more than the specified number
                       of bytes. (snprintf (buf, 3, "%d %d", 4567, 89) writes
                       '4', '5', '6' into buf, not '4', '5', '\0'.)
                     - Although the gl_SNPRINTF_RETVAL_C99 test fails, snprintf
                       allows us to recognize the case of an insufficient
                       buffer size: it returns -1 in this case.
                   On native Windows systems (such as mingw) where the OS is
                   Windows Vista, the use of %n in format strings by default
                   crashes the program. See
                     <https://gcc.gnu.org/ml/gcc/2007-06/msg00122.html> and
                     <https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/set-printf-count-output>
                   So we should avoid %n in this situation.  */
                            *fbp.offset(1 as libc::c_int as isize) =
                                '\u{0}' as i32 as libc::c_char;
                            /* AIX <= 5.1, HP-UX, IRIX, OSF/1, Solaris <= 9, BeOS */
                            /* Construct the arguments for calling snprintf or sprintf.  */
                            prefix_count = 0 as libc::c_int as libc::c_uint;
                            if 0 as libc::c_int == 0 &&
                                   (*dp).width_arg_index !=
                                       !(0 as libc::c_int as size_t) {
                                if !((*a.arg.offset((*dp).width_arg_index as
                                                        isize)).type_0 as
                                         libc::c_uint ==
                                         TYPE_INT as libc::c_int as
                                             libc::c_uint) {
                                    abort();
                                }
                                let fresh18 = prefix_count;
                                prefix_count = prefix_count.wrapping_add(1);
                                prefixes[fresh18 as usize] =
                                    (*a.arg.offset((*dp).width_arg_index as
                                                       isize)).a.a_int
                            }
                            if 0 as libc::c_int == 0 &&
                                   (*dp).precision_arg_index !=
                                       !(0 as libc::c_int as size_t) {
                                if !((*a.arg.offset((*dp).precision_arg_index
                                                        as isize)).type_0 as
                                         libc::c_uint ==
                                         TYPE_INT as libc::c_int as
                                             libc::c_uint) {
                                    abort();
                                }
                                let fresh19 = prefix_count;
                                prefix_count = prefix_count.wrapping_add(1);
                                prefixes[fresh19 as usize] =
                                    (*a.arg.offset((*dp).precision_arg_index
                                                       as isize)).a.a_int
                            }
                            /* The SNPRINTF result is appended after result[0..length].
                   The latter is an array of DCHAR_T; SNPRINTF appends an
                   array of TCHAR_T to it.  This is possible because
                   sizeof (TCHAR_T) divides sizeof (DCHAR_T) and
                   alignof (TCHAR_T) <= alignof (DCHAR_T).  */
                            /* Ensure that maxlen below will be >= 2.  Needed on BeOS,
                   where an snprintf() with maxlen==1 acts like sprintf().  */
                            if xsum(length,
                                    (2 as libc::c_int as
                                         libc::c_ulong).wrapping_add((::std::mem::size_of::<libc::c_char>()
                                                                          as
                                                                          libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                                                          as
                                                                                                          libc::c_ulong)).wrapping_sub(1
                                                                                                                                           as
                                                                                                                                           libc::c_int
                                                                                                                                           as
                                                                                                                                           libc::c_ulong).wrapping_div((::std::mem::size_of::<libc::c_char>()
                                                                                                                                                                            as
                                                                                                                                                                            libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                                                                                                                                                            as
                                                                                                                                                                                                            libc::c_ulong)))
                                   > allocated {
                                let mut memory_size_1: size_t = 0;
                                let mut memory_1: *mut libc::c_char =
                                    0 as *mut libc::c_char;
                                allocated =
                                    if allocated >
                                           0 as libc::c_int as libc::c_ulong {
                                        if allocated <=
                                               (18446744073709551615 as
                                                    libc::c_ulong).wrapping_div(2
                                                                                    as
                                                                                    libc::c_int
                                                                                    as
                                                                                    libc::c_ulong)
                                           {
                                            allocated.wrapping_mul(2 as
                                                                       libc::c_int
                                                                       as
                                                                       libc::c_ulong)
                                        } else {
                                            18446744073709551615 as
                                                libc::c_ulong
                                        }
                                    } else {
                                        12 as libc::c_int as libc::c_ulong
                                    };
                                if xsum(length,
                                        (2 as libc::c_int as
                                             libc::c_ulong).wrapping_add((::std::mem::size_of::<libc::c_char>()
                                                                              as
                                                                              libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                                                              as
                                                                                                              libc::c_ulong)).wrapping_sub(1
                                                                                                                                               as
                                                                                                                                               libc::c_int
                                                                                                                                               as
                                                                                                                                               libc::c_ulong).wrapping_div((::std::mem::size_of::<libc::c_char>()
                                                                                                                                                                                as
                                                                                                                                                                                libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                                                                                                                                                                as
                                                                                                                                                                                                                libc::c_ulong)))
                                       > allocated {
                                    allocated =
                                        xsum(length,
                                             (2 as libc::c_int as
                                                  libc::c_ulong).wrapping_add((::std::mem::size_of::<libc::c_char>()
                                                                                   as
                                                                                   libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                                                                   as
                                                                                                                   libc::c_ulong)).wrapping_sub(1
                                                                                                                                                    as
                                                                                                                                                    libc::c_int
                                                                                                                                                    as
                                                                                                                                                    libc::c_ulong).wrapping_div((::std::mem::size_of::<libc::c_char>()
                                                                                                                                                                                     as
                                                                                                                                                                                     libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                                                                                                                                                                     as
                                                                                                                                                                                                                     libc::c_ulong)))
                                }
                                memory_size_1 =
                                    if allocated <=
                                           (18446744073709551615 as
                                                libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                                as
                                                                                libc::c_ulong)
                                       {
                                        allocated.wrapping_mul(::std::mem::size_of::<libc::c_char>()
                                                                   as
                                                                   libc::c_ulong)
                                    } else {
                                        18446744073709551615 as libc::c_ulong
                                    };
                                if memory_size_1 ==
                                       18446744073709551615 as libc::c_ulong {
                                    current_block = 3630591880094558253;
                                    break ;
                                }
                                if result == resultbuf || result.is_null() {
                                    memory_1 =
                                        malloc(memory_size_1) as
                                            *mut libc::c_char
                                } else {
                                    memory_1 =
                                        realloc(result as *mut libc::c_void,
                                                memory_size_1) as
                                            *mut libc::c_char
                                }
                                if memory_1.is_null() {
                                    current_block = 3630591880094558253;
                                    break ;
                                }
                                if result == resultbuf &&
                                       length >
                                           0 as libc::c_int as libc::c_ulong {
                                    memcpy(memory_1 as *mut libc::c_void,
                                           result as *const libc::c_void,
                                           length);
                                }
                                result = memory_1
                            }
                            /* Prepare checking whether snprintf returns the count
                   via %n.  */
                            *result.offset(length as isize) =
                                '\u{0}' as i32 as libc::c_char;
                            orig_errno = *__errno_location();
                            loop  {
                                let mut count: libc::c_int =
                                    -(1 as libc::c_int);
                                let mut retcount: libc::c_int =
                                    0 as libc::c_int;
                                let mut maxlen: size_t =
                                    allocated.wrapping_sub(length);
                                /* SNPRINTF can fail if its second argument is
                       > INT_MAX.  */
                                if maxlen >
                                       (2147483647 as libc::c_int as
                                            libc::c_ulong).wrapping_div((::std::mem::size_of::<libc::c_char>()
                                                                             as
                                                                             libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                                                             as
                                                                                                             libc::c_ulong))
                                   {
                                    maxlen =
                                        (2147483647 as libc::c_int as
                                             libc::c_ulong).wrapping_div((::std::mem::size_of::<libc::c_char>()
                                                                              as
                                                                              libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                                                              as
                                                                                                              libc::c_ulong))
                                }
                                maxlen =
                                    maxlen.wrapping_mul((::std::mem::size_of::<libc::c_char>()
                                                             as
                                                             libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                                             as
                                                                                             libc::c_ulong));
                                *__errno_location() = 0 as libc::c_int;
                                match type_0 as libc::c_uint {
                                    1 => {
                                        let mut arg: libc::c_int =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_schar
                                                as libc::c_int;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf, arg,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    2 => {
                                        let mut arg_0: libc::c_uint =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_uchar
                                                as libc::c_uint;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             arg_0,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_0,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_0,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    3 => {
                                        let mut arg_1: libc::c_int =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_short
                                                as libc::c_int;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             arg_1,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_1,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_1,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    4 => {
                                        let mut arg_2: libc::c_uint =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_ushort
                                                as libc::c_uint;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             arg_2,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_2,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_2,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    5 => {
                                        let mut arg_3: libc::c_int =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_int;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             arg_3,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_3,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_3,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    6 => {
                                        let mut arg_4: libc::c_uint =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_uint;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             arg_4,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_4,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_4,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    7 => {
                                        let mut arg_5: libc::c_long =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_longint;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             arg_5,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_5,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_5,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    8 => {
                                        let mut arg_6: libc::c_ulong =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_ulongint;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             arg_6,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_6,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_6,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    9 => {
                                        let mut arg_7: libc::c_longlong =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_longlongint;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             arg_7,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_7,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_7,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    10 => {
                                        let mut arg_8: libc::c_ulonglong =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_ulonglongint;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             arg_8,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_8,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_8,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    11 => {
                                        let mut arg_9: libc::c_double =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_double;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             arg_9,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_9,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_9,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    13 => {
                                        let mut arg_11: libc::c_int =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_char;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             arg_11,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_11,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_11,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    14 => {
                                        let mut arg_12: wint_t =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_wide_char;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             arg_12,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_12,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_12,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    15 => {
                                        let mut arg_13: *const libc::c_char =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_string;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             arg_13,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_13,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_13,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    16 => {
                                        let mut arg_14: *const wchar_t =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_wide_string;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             arg_14,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_14,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_14,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    17 => {
                                        let mut arg_15: *mut libc::c_void =
                                            (*a.arg.offset((*dp).arg_index as
                                                               isize)).a.a_pointer;
                                        match prefix_count {
                                            0 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             arg_15,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            1 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_15,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            2 => {
                                                retcount =
                                                    snprintf(result.offset(length
                                                                               as
                                                                               isize),
                                                             maxlen, buf,
                                                             prefixes[0 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             prefixes[1 as
                                                                          libc::c_int
                                                                          as
                                                                          usize],
                                                             arg_15,
                                                             &mut count as
                                                                 *mut libc::c_int)
                                            }
                                            _ => { abort(); }
                                        }
                                    }
                                    _ => { abort(); }
                                }
                                /* Portability: Not all implementations of snprintf()
                       are ISO C 99 compliant.  Determine the number of
                       bytes that snprintf() has produced or would have
                       produced.  */
                                if count >= 0 as libc::c_int {
                                    /* Verify that snprintf() has NUL-terminated its
                           result.  */
                                    if (count as libc::c_uint as
                                            libc::c_ulong) < maxlen &&
                                           *result.offset(length as
                                                              isize).offset(count
                                                                                as
                                                                                isize)
                                               as libc::c_int !=
                                               '\u{0}' as i32 {
                                        abort();
                                    }
                                    /* Portability hack.  */
                                    if retcount > count { count = retcount }
                                } else if *fbp.offset(1 as libc::c_int as
                                                          isize) as
                                              libc::c_int != '\u{0}' as i32 {
                                    /* snprintf() doesn't understand the '%n'
                           directive.  */
                                    /* Don't use the '%n' directive; instead, look
                               at the snprintf() return value.  */
                                    *fbp.offset(1 as libc::c_int as isize) =
                                        '\u{0}' as i32 as libc::c_char;
                                    continue ;
                                } else if !(retcount < 0 as libc::c_int) {
                                    count = retcount
                                }
                                /* Look at the snprintf() return value.  */
                                /* Attempt to handle failure.  */
                                if count < 0 as libc::c_int {
                                    /* SNPRINTF or sprintf failed.  Use the errno that it
                           has set, if any.  */
                                    if *__errno_location() == 0 as libc::c_int
                                       {
                                        if (*dp).conversion as libc::c_int ==
                                               'c' as i32 ||
                                               (*dp).conversion as libc::c_int
                                                   == 's' as i32 {
                                            *__errno_location() =
                                                84 as libc::c_int
                                        } else {
                                            *__errno_location() =
                                                22 as libc::c_int
                                        }
                                    }
                                    if !(result == resultbuf ||
                                             result.is_null()) {
                                        rpl_free(result as *mut libc::c_void);
                                    }
                                    if !buf_malloced.is_null() {
                                        rpl_free(buf_malloced as
                                                     *mut libc::c_void);
                                    }
                                    if d.dir !=
                                           d.direct_alloc_dir.as_mut_ptr() {
                                        rpl_free(d.dir as *mut libc::c_void);
                                    }
                                    if a.arg !=
                                           a.direct_alloc_arg.as_mut_ptr() {
                                        rpl_free(a.arg as *mut libc::c_void);
                                    }
                                    return 0 as *mut libc::c_char
                                }
                                /* Handle overflow of the allocated buffer.
                       If such an overflow occurs, a C99 compliant snprintf()
                       returns a count >= maxlen.  However, a non-compliant
                       snprintf() function returns only count = maxlen - 1.  To
                       cover both cases, test whether count >= maxlen - 1.  */
                                if (count as
                                        libc::c_uint).wrapping_add(1 as
                                                                       libc::c_int
                                                                       as
                                                                       libc::c_uint)
                                       as libc::c_ulong >= maxlen {
                                    /* If maxlen already has attained its allowed maximum,
                           allocating more memory will not increase maxlen.
                           Instead of looping, bail out.  */
                                    if maxlen ==
                                           (2147483647 as libc::c_int as
                                                libc::c_ulong).wrapping_div((::std::mem::size_of::<libc::c_char>()
                                                                                 as
                                                                                 libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                                                                 as
                                                                                                                 libc::c_ulong))
                                       {
                                        current_block = 2933827379788023787;
                                        break 's_174 ;
                                    }
                                    /* Need at least (count + 1) * sizeof (TCHAR_T)
                               bytes.  (The +1 is for the trailing NUL.)
                               But ask for (count + 2) * sizeof (TCHAR_T)
                               bytes, so that in the next round, we likely get
                                 maxlen > (unsigned int) count + 1
                               and so we don't get here again.
                               And allocate proportionally, to avoid looping
                               eternally if snprintf() reports a too small
                               count.  */
                                    let mut n_2: size_t =
                                        xmax(xsum(length,
                                                  ((count as
                                                        libc::c_uint).wrapping_add(2
                                                                                       as
                                                                                       libc::c_int
                                                                                       as
                                                                                       libc::c_uint)
                                                       as
                                                       libc::c_ulong).wrapping_add((::std::mem::size_of::<libc::c_char>()
                                                                                        as
                                                                                        libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                                                                        as
                                                                                                                        libc::c_ulong)).wrapping_sub(1
                                                                                                                                                         as
                                                                                                                                                         libc::c_int
                                                                                                                                                         as
                                                                                                                                                         libc::c_ulong).wrapping_div((::std::mem::size_of::<libc::c_char>()
                                                                                                                                                                                          as
                                                                                                                                                                                          libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                                                                                                                                                                          as
                                                                                                                                                                                                                          libc::c_ulong))),
                                             if allocated <=
                                                    (18446744073709551615 as
                                                         libc::c_ulong).wrapping_div(2
                                                                                         as
                                                                                         libc::c_int
                                                                                         as
                                                                                         libc::c_ulong)
                                                {
                                                 allocated.wrapping_mul(2 as
                                                                            libc::c_int
                                                                            as
                                                                            libc::c_ulong)
                                             } else {
                                                 18446744073709551615 as
                                                     libc::c_ulong
                                             });
                                    if !(n_2 > allocated) { continue ; }
                                    let mut memory_size_2: size_t = 0;
                                    let mut memory_2: *mut libc::c_char =
                                        0 as *mut libc::c_char;
                                    allocated =
                                        if allocated >
                                               0 as libc::c_int as
                                                   libc::c_ulong {
                                            if allocated <=
                                                   (18446744073709551615 as
                                                        libc::c_ulong).wrapping_div(2
                                                                                        as
                                                                                        libc::c_int
                                                                                        as
                                                                                        libc::c_ulong)
                                               {
                                                allocated.wrapping_mul(2 as
                                                                           libc::c_int
                                                                           as
                                                                           libc::c_ulong)
                                            } else {
                                                18446744073709551615 as
                                                    libc::c_ulong
                                            }
                                        } else {
                                            12 as libc::c_int as libc::c_ulong
                                        };
                                    if n_2 > allocated { allocated = n_2 }
                                    memory_size_2 =
                                        if allocated <=
                                               (18446744073709551615 as
                                                    libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                                    as
                                                                                    libc::c_ulong)
                                           {
                                            allocated.wrapping_mul(::std::mem::size_of::<libc::c_char>()
                                                                       as
                                                                       libc::c_ulong)
                                        } else {
                                            18446744073709551615 as
                                                libc::c_ulong
                                        };
                                    if memory_size_2 ==
                                           18446744073709551615 as
                                               libc::c_ulong {
                                        current_block = 3630591880094558253;
                                        break 's_174 ;
                                    }
                                    if result == resultbuf || result.is_null()
                                       {
                                        memory_2 =
                                            malloc(memory_size_2) as
                                                *mut libc::c_char
                                    } else {
                                        memory_2 =
                                            realloc(result as
                                                        *mut libc::c_void,
                                                    memory_size_2) as
                                                *mut libc::c_char
                                    }
                                    if memory_2.is_null() {
                                        current_block = 3630591880094558253;
                                        break 's_174 ;
                                    }
                                    if result == resultbuf &&
                                           length >
                                               0 as libc::c_int as
                                                   libc::c_ulong {
                                        memcpy(memory_2 as *mut libc::c_void,
                                               result as *const libc::c_void,
                                               length);
                                    }
                                    result = memory_2
                                } else {
                                    /* Here count <= allocated - length.  */
                                    /* Perform padding.  */
                                    /* Here still count <= allocated - length.  */
                                    /* The snprintf() result did fit.  */
                                    length =
                                        (length as
                                             libc::c_ulong).wrapping_add(count
                                                                             as
                                                                             libc::c_ulong)
                                            as size_t as size_t;
                                    break ;
                                }
                            }
                            *__errno_location() = orig_errno
                        }
                    }
                    cp = (*dp).dir_end;
                    i = i.wrapping_add(1);
                    dp = dp.offset(1)
                }
            match current_block {
                14540000294252553875 =>
                /* Add the final NUL.  */
                {
                    if xsum(length, 1 as libc::c_int as size_t) > allocated {
                        let mut memory_size_3: size_t = 0;
                        let mut memory_3: *mut libc::c_char =
                            0 as *mut libc::c_char;
                        allocated =
                            if allocated > 0 as libc::c_int as libc::c_ulong {
                                if allocated <=
                                       (18446744073709551615 as
                                            libc::c_ulong).wrapping_div(2 as
                                                                            libc::c_int
                                                                            as
                                                                            libc::c_ulong)
                                   {
                                    allocated.wrapping_mul(2 as libc::c_int as
                                                               libc::c_ulong)
                                } else {
                                    18446744073709551615 as libc::c_ulong
                                }
                            } else { 12 as libc::c_int as libc::c_ulong };
                        if xsum(length, 1 as libc::c_int as size_t) >
                               allocated {
                            allocated =
                                xsum(length, 1 as libc::c_int as size_t)
                        }
                        memory_size_3 =
                            if allocated <=
                                   (18446744073709551615 as
                                        libc::c_ulong).wrapping_div(::std::mem::size_of::<libc::c_char>()
                                                                        as
                                                                        libc::c_ulong)
                               {
                                allocated.wrapping_mul(::std::mem::size_of::<libc::c_char>()
                                                           as libc::c_ulong)
                            } else { 18446744073709551615 as libc::c_ulong };
                        if memory_size_3 ==
                               18446744073709551615 as libc::c_ulong {
                            current_block = 3630591880094558253;
                        } else {
                            if result == resultbuf || result.is_null() {
                                memory_3 =
                                    malloc(memory_size_3) as *mut libc::c_char
                            } else {
                                memory_3 =
                                    realloc(result as *mut libc::c_void,
                                            memory_size_3) as
                                        *mut libc::c_char
                            }
                            if memory_3.is_null() {
                                current_block = 3630591880094558253;
                            } else {
                                if result == resultbuf &&
                                       length >
                                           0 as libc::c_int as libc::c_ulong {
                                    memcpy(memory_3 as *mut libc::c_void,
                                           result as *const libc::c_void,
                                           length);
                                }
                                result = memory_3;
                                current_block = 310153692251169202;
                            }
                        }
                    } else { current_block = 310153692251169202; }
                    match current_block {
                        3630591880094558253 => { }
                        _ => {
                            *result.offset(length as isize) =
                                '\u{0}' as i32 as libc::c_char;
                            if result != resultbuf &&
                                   length.wrapping_add(1 as libc::c_int as
                                                           libc::c_ulong) <
                                       allocated {
                                /* Shrink the allocated memory if possible.  */
                                let mut memory_4: *mut libc::c_char =
                                    0 as *mut libc::c_char;
                                memory_4 =
                                    realloc(result as *mut libc::c_void,
                                            length.wrapping_add(1 as
                                                                    libc::c_int
                                                                    as
                                                                    libc::c_ulong).wrapping_mul(::std::mem::size_of::<libc::c_char>()
                                                                                                    as
                                                                                                    libc::c_ulong))
                                        as *mut libc::c_char;
                                if !memory_4.is_null() { result = memory_4 }
                            }
                            if !buf_malloced.is_null() {
                                rpl_free(buf_malloced as *mut libc::c_void);
                            }
                            if d.dir != d.direct_alloc_dir.as_mut_ptr() {
                                rpl_free(d.dir as *mut libc::c_void);
                            }
                            if a.arg != a.direct_alloc_arg.as_mut_ptr() {
                                rpl_free(a.arg as *mut libc::c_void);
                            }
                            *lengthp = length;
                            /* Note that we can produce a big string of a length > INT_MAX.  POSIX
       says that snprintf() fails with errno = EOVERFLOW in this case, but
       that's only because snprintf() returns an 'int'.  This function does
       not have this limitation.  */
                            return result
                        }
                    }
                }
                2933827379788023787 => {
                    if !(result == resultbuf || result.is_null()) {
                        rpl_free(result as *mut libc::c_void);
                    }
                    if !buf_malloced.is_null() {
                        rpl_free(buf_malloced as *mut libc::c_void);
                    }
                    if d.dir != d.direct_alloc_dir.as_mut_ptr() {
                        rpl_free(d.dir as *mut libc::c_void);
                    }
                    if a.arg != a.direct_alloc_arg.as_mut_ptr() {
                        rpl_free(a.arg as *mut libc::c_void);
                    }
                    *__errno_location() = 75 as libc::c_int;
                    return 0 as *mut libc::c_char
                }
                _ => { }
            }
            if !(result == resultbuf || result.is_null()) {
                rpl_free(result as *mut libc::c_void);
            }
            if !buf_malloced.is_null() {
                rpl_free(buf_malloced as *mut libc::c_void);
            }
        }
        _ => { }
    }
    if d.dir != d.direct_alloc_dir.as_mut_ptr() {
        rpl_free(d.dir as *mut libc::c_void);
    }
    if a.arg != a.direct_alloc_arg.as_mut_ptr() {
        rpl_free(a.arg as *mut libc::c_void);
    }
    *__errno_location() = 12 as libc::c_int;
    return 0 as *mut libc::c_char;
}
