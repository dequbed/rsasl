use ::libc;
extern "C" {
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
    fn rpl_free(_: *mut libc::c_void);
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    fn __errno_location() -> *mut libc::c_int;
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type wchar_t = libc::c_int;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct arguments {
    pub count: size_t,
    pub arg: *mut argument,
    pub direct_alloc_arg: [argument; 7],
}
/* Parse printf format string.
   Copyright (C) 1999, 2002-2003, 2005, 2007, 2010-2021 Free Software
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
     STATIC             Set to 'static' to declare the function static.  */
/* for __GLIBC__, __UCLIBC__ */
/* Flags */
/* ' flag */
/* - flag */
/* + flag */
/* space flag */
/* # flag */
/* I flag, uses localized digits */
/* arg_index value indicating that no argument is consumed.  */
/* xxx_directive: A parsed directive.
   xxx_directives: A parsed format string.  */
/* Number of directly allocated directives (no malloc() needed).  */
/* A parsed directive.  */
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
/* A parsed format string.  */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct char_directives {
    pub count: size_t,
    pub dir: *mut char_directive,
    pub max_width_length: size_t,
    pub max_precision_length: size_t,
    pub direct_alloc_dir: [char_directive; 7],
}
pub type intmax_t = __intmax_t;
pub type __intmax_t = libc::c_long;
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
#[inline]
unsafe extern "C" fn xsum(mut size1: size_t, mut size2: size_t) -> size_t {
    let mut sum: size_t = size1.wrapping_add(size2);
    return if sum >= size1 {
               sum
           } else { 18446744073709551615 as libc::c_ulong };
}
/* Parses the format string.  Fills in the number N of directives, and fills
   in directives[0], ..., directives[N-1], and sets directives[N].dir_start
   to the end of the format string.  Also fills in the arg_type fields of the
   arguments and the needed count of arguments.  */
/* Formatted output to strings.
   Copyright (C) 1999-2000, 2002-2003, 2006-2021 Free Software Foundation, Inc.

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
     CHAR_T             The element type of the format string.
     CHAR_T_ONLY_ASCII  Set to 1 to enable verification that all characters
                        in the format string are ASCII.
     DIRECTIVE          Structure denoting a format directive.
                        Depends on CHAR_T.
     DIRECTIVES         Structure denoting the set of format directives of a
                        format string.  Depends on CHAR_T.
     PRINTF_PARSE       Function that parses a format string.
                        Depends on CHAR_T.
     STATIC             Set to 'static' to declare the function static.
     ENABLE_UNISTDIO    Set to 1 to enable the unistdio extensions.  */
/* Specification.  */
/* Default parameters.  */
/* Get size_t, NULL.  */
/* Get intmax_t.  */
/* malloc(), realloc(), free().  */
/* memcpy().  */
/* errno.  */
/* Checked size_t computations.  */
#[no_mangle]
pub unsafe extern "C" fn printf_parse(mut format: *const libc::c_char,
                                      mut d: *mut char_directives,
                                      mut a: *mut arguments) -> libc::c_int {
    let mut current_block: u64; /* pointer into format */
    let mut cp: *const libc::c_char =
        format; /* number of regular arguments consumed */
    let mut arg_posn: size_t =
        0 as libc::c_int as size_t; /* allocated elements of d->dir */
    let mut d_allocated: size_t = 0; /* allocated elements of a->arg */
    let mut a_allocated: size_t = 0;
    let mut max_width_length: size_t = 0 as libc::c_int as size_t;
    let mut max_precision_length: size_t = 0 as libc::c_int as size_t;
    (*d).count = 0 as libc::c_int as size_t;
    d_allocated = 7 as libc::c_int as size_t;
    (*d).dir = (*d).direct_alloc_dir.as_mut_ptr();
    (*a).count = 0 as libc::c_int as size_t;
    a_allocated = 7 as libc::c_int as size_t;
    (*a).arg = (*a).direct_alloc_arg.as_mut_ptr();
    loop 
         /* Overflow, would lead to out of memory.  */
         /* Out of memory.  */
         /* Ambiguous type for positional argument.  */
         {
        if !(*cp as libc::c_int != '\u{0}' as i32) {
            current_block =
                13976402388691103242; /* pointer to next directive */
            break ;
        }
        let fresh0 = cp;
        cp = cp.offset(1);
        let mut c: libc::c_char = *fresh0;
        if !(c as libc::c_int == '%' as i32) { continue ; }
        let mut arg_index: size_t = !(0 as libc::c_int as size_t);
        let mut dp: *mut char_directive =
            &mut *(*d).dir.offset((*d).count as isize) as *mut char_directive;
        /* Initialize the next directive.  */
        (*dp).dir_start = cp.offset(-(1 as libc::c_int as isize));
        (*dp).flags = 0 as libc::c_int;
        (*dp).width_start = 0 as *const libc::c_char;
        (*dp).width_end = 0 as *const libc::c_char;
        (*dp).width_arg_index = !(0 as libc::c_int as size_t);
        (*dp).precision_start = 0 as *const libc::c_char;
        (*dp).precision_end = 0 as *const libc::c_char;
        (*dp).precision_arg_index = !(0 as libc::c_int as size_t);
        (*dp).arg_index = !(0 as libc::c_int as size_t);
        /* Test for positional argument.  */
        if *cp as libc::c_int >= '0' as i32 &&
               *cp as libc::c_int <= '9' as i32 {
            let mut np: *const libc::c_char = 0 as *const libc::c_char;
            np = cp;
            while *np as libc::c_int >= '0' as i32 &&
                      *np as libc::c_int <= '9' as i32 {
                np = np.offset(1)
            }
            if *np as libc::c_int == '$' as i32 {
                let mut n: size_t = 0 as libc::c_int as size_t;
                np = cp;
                while *np as libc::c_int >= '0' as i32 &&
                          *np as libc::c_int <= '9' as i32 {
                    n =
                        xsum(if n <=
                                    (18446744073709551615 as
                                         libc::c_ulong).wrapping_div(10 as
                                                                         libc::c_int
                                                                         as
                                                                         libc::c_ulong)
                                {
                                 n.wrapping_mul(10 as libc::c_int as
                                                    libc::c_ulong)
                             } else { 18446744073709551615 as libc::c_ulong },
                             (*np as libc::c_int - '0' as i32) as size_t);
                    np = np.offset(1)
                }
                if n == 0 as libc::c_int as libc::c_ulong {
                    /* Positional argument 0.  */
                    current_block = 9180984893592688305;
                    break ;
                } else if n == 18446744073709551615 as libc::c_ulong {
                    /* n too large, would lead to out of memory later.  */
                    current_block = 9180984893592688305;
                    break ;
                } else {
                    arg_index =
                        n.wrapping_sub(1 as libc::c_int as libc::c_ulong);
                    cp = np.offset(1 as libc::c_int as isize)
                }
            }
        }
        loop 
             /* Read the flags.  */
             {
            if *cp as libc::c_int == '\'' as i32 {
                (*dp).flags |= 1 as libc::c_int;
                cp = cp.offset(1)
            } else if *cp as libc::c_int == '-' as i32 {
                (*dp).flags |= 2 as libc::c_int;
                cp = cp.offset(1)
            } else if *cp as libc::c_int == '+' as i32 {
                (*dp).flags |= 4 as libc::c_int;
                cp = cp.offset(1)
            } else if *cp as libc::c_int == ' ' as i32 {
                (*dp).flags |= 8 as libc::c_int;
                cp = cp.offset(1)
            } else if *cp as libc::c_int == '#' as i32 {
                (*dp).flags |= 16 as libc::c_int;
                cp = cp.offset(1)
            } else if *cp as libc::c_int == '0' as i32 {
                (*dp).flags |= 32 as libc::c_int;
                cp = cp.offset(1)
            } else {
                if !(*cp as libc::c_int == 'I' as i32) { break ; }
                (*dp).flags |= 64 as libc::c_int;
                cp = cp.offset(1)
            }
        }
        /* Parse the field width.  */
        if *cp as libc::c_int == '*' as i32 {
            (*dp).width_start = cp;
            cp = cp.offset(1);
            (*dp).width_end = cp;
            if max_width_length < 1 as libc::c_int as libc::c_ulong {
                max_width_length = 1 as libc::c_int as size_t
            }
            /* Test for positional argument.  */
            if *cp as libc::c_int >= '0' as i32 &&
                   *cp as libc::c_int <= '9' as i32 {
                let mut np_0: *const libc::c_char = 0 as *const libc::c_char;
                np_0 = cp;
                while *np_0 as libc::c_int >= '0' as i32 &&
                          *np_0 as libc::c_int <= '9' as i32 {
                    np_0 = np_0.offset(1)
                }
                if *np_0 as libc::c_int == '$' as i32 {
                    let mut n_0: size_t = 0 as libc::c_int as size_t;
                    np_0 = cp;
                    while *np_0 as libc::c_int >= '0' as i32 &&
                              *np_0 as libc::c_int <= '9' as i32 {
                        n_0 =
                            xsum(if n_0 <=
                                        (18446744073709551615 as
                                             libc::c_ulong).wrapping_div(10 as
                                                                             libc::c_int
                                                                             as
                                                                             libc::c_ulong)
                                    {
                                     n_0.wrapping_mul(10 as libc::c_int as
                                                          libc::c_ulong)
                                 } else {
                                     18446744073709551615 as libc::c_ulong
                                 },
                                 (*np_0 as libc::c_int - '0' as i32) as
                                     size_t);
                        np_0 = np_0.offset(1)
                    }
                    if n_0 == 0 as libc::c_int as libc::c_ulong {
                        /* Positional argument 0.  */
                        current_block = 9180984893592688305;
                        break ;
                    } else if n_0 == 18446744073709551615 as libc::c_ulong {
                        /* n too large, would lead to out of memory later.  */
                        current_block = 9180984893592688305;
                        break ;
                    } else {
                        (*dp).width_arg_index =
                            n_0.wrapping_sub(1 as libc::c_int as
                                                 libc::c_ulong);
                        cp = np_0.offset(1 as libc::c_int as isize)
                    }
                }
            }
            if (*dp).width_arg_index == !(0 as libc::c_int as size_t) {
                let fresh1 = arg_posn;
                arg_posn = arg_posn.wrapping_add(1);
                (*dp).width_arg_index = fresh1;
                if (*dp).width_arg_index == !(0 as libc::c_int as size_t) {
                    /* arg_posn wrapped around.  */
                    current_block = 9180984893592688305;
                    break ;
                }
            }
            let mut n_1: size_t = (*dp).width_arg_index;
            if n_1 >= a_allocated {
                let mut memory_size: size_t = 0;
                let mut memory: *mut argument = 0 as *mut argument;
                a_allocated =
                    if a_allocated <=
                           (18446744073709551615 as
                                libc::c_ulong).wrapping_div(2 as libc::c_int
                                                                as
                                                                libc::c_ulong)
                       {
                        a_allocated.wrapping_mul(2 as libc::c_int as
                                                     libc::c_ulong)
                    } else { 18446744073709551615 as libc::c_ulong };
                if a_allocated <= n_1 {
                    a_allocated = xsum(n_1, 1 as libc::c_int as size_t)
                }
                memory_size =
                    if a_allocated <=
                           (18446744073709551615 as
                                libc::c_ulong).wrapping_div(::std::mem::size_of::<argument>()
                                                                as
                                                                libc::c_ulong)
                       {
                        a_allocated.wrapping_mul(::std::mem::size_of::<argument>()
                                                     as libc::c_ulong)
                    } else { 18446744073709551615 as libc::c_ulong };
                if memory_size == 18446744073709551615 as libc::c_ulong {
                    current_block = 16586880076602670907;
                    break ;
                }
                memory =
                    if (*a).arg != (*a).direct_alloc_arg.as_mut_ptr() {
                        realloc((*a).arg as *mut libc::c_void, memory_size)
                    } else { malloc(memory_size) } as *mut argument;
                if memory.is_null() {
                    current_block = 16586880076602670907;
                    break ;
                }
                if (*a).arg == (*a).direct_alloc_arg.as_mut_ptr() {
                    memcpy(memory as *mut libc::c_void,
                           (*a).arg as *const libc::c_void,
                           (*a).count.wrapping_mul(::std::mem::size_of::<argument>()
                                                       as libc::c_ulong));
                }
                (*a).arg = memory
            }
            while (*a).count <= n_1 {
                let fresh2 = (*a).count;
                (*a).count = (*a).count.wrapping_add(1);
                (*(*a).arg.offset(fresh2 as isize)).type_0 = TYPE_NONE
            }
            if (*(*a).arg.offset(n_1 as isize)).type_0 as libc::c_uint ==
                   TYPE_NONE as libc::c_int as libc::c_uint {
                (*(*a).arg.offset(n_1 as isize)).type_0 = TYPE_INT
            } else if (*(*a).arg.offset(n_1 as isize)).type_0 as libc::c_uint
                          != TYPE_INT as libc::c_int as libc::c_uint {
                current_block = 9180984893592688305;
                break ;
            }
        } else if *cp as libc::c_int >= '0' as i32 &&
                      *cp as libc::c_int <= '9' as i32 {
            let mut width_length: size_t = 0;
            (*dp).width_start = cp;
            while *cp as libc::c_int >= '0' as i32 &&
                      *cp as libc::c_int <= '9' as i32 {
                cp = cp.offset(1)
            }
            (*dp).width_end = cp;
            width_length =
                (*dp).width_end.offset_from((*dp).width_start) as
                    libc::c_long as size_t;
            if max_width_length < width_length {
                max_width_length = width_length
            }
        }
        /* Parse the precision.  */
        if *cp as libc::c_int == '.' as i32 {
            cp = cp.offset(1);
            if *cp as libc::c_int == '*' as i32 {
                (*dp).precision_start =
                    cp.offset(-(1 as libc::c_int as isize));
                cp = cp.offset(1);
                (*dp).precision_end = cp;
                if max_precision_length < 2 as libc::c_int as libc::c_ulong {
                    max_precision_length = 2 as libc::c_int as size_t
                }
                /* Test for positional argument.  */
                if *cp as libc::c_int >= '0' as i32 &&
                       *cp as libc::c_int <= '9' as i32 {
                    let mut np_1: *const libc::c_char =
                        0 as *const libc::c_char;
                    np_1 = cp;
                    while *np_1 as libc::c_int >= '0' as i32 &&
                              *np_1 as libc::c_int <= '9' as i32 {
                        np_1 = np_1.offset(1)
                    }
                    if *np_1 as libc::c_int == '$' as i32 {
                        let mut n_2: size_t = 0 as libc::c_int as size_t;
                        np_1 = cp;
                        while *np_1 as libc::c_int >= '0' as i32 &&
                                  *np_1 as libc::c_int <= '9' as i32 {
                            n_2 =
                                xsum(if n_2 <=
                                            (18446744073709551615 as
                                                 libc::c_ulong).wrapping_div(10
                                                                                 as
                                                                                 libc::c_int
                                                                                 as
                                                                                 libc::c_ulong)
                                        {
                                         n_2.wrapping_mul(10 as libc::c_int as
                                                              libc::c_ulong)
                                     } else {
                                         18446744073709551615 as libc::c_ulong
                                     },
                                     (*np_1 as libc::c_int - '0' as i32) as
                                         size_t);
                            np_1 = np_1.offset(1)
                        }
                        if n_2 == 0 as libc::c_int as libc::c_ulong {
                            /* Positional argument 0.  */
                            current_block = 9180984893592688305;
                            break ;
                        } else if n_2 == 18446744073709551615 as libc::c_ulong
                         {
                            /* n too large, would lead to out of memory
                               later.  */
                            current_block = 9180984893592688305;
                            break ;
                        } else {
                            (*dp).precision_arg_index =
                                n_2.wrapping_sub(1 as libc::c_int as
                                                     libc::c_ulong);
                            cp = np_1.offset(1 as libc::c_int as isize)
                        }
                    }
                }
                if (*dp).precision_arg_index == !(0 as libc::c_int as size_t)
                   {
                    let fresh3 = arg_posn;
                    arg_posn = arg_posn.wrapping_add(1);
                    (*dp).precision_arg_index = fresh3;
                    if (*dp).precision_arg_index ==
                           !(0 as libc::c_int as size_t) {
                        /* arg_posn wrapped around.  */
                        current_block = 9180984893592688305;
                        break ;
                    }
                }
                let mut n_3: size_t = (*dp).precision_arg_index;
                if n_3 >= a_allocated {
                    let mut memory_size_0: size_t = 0;
                    let mut memory_0: *mut argument = 0 as *mut argument;
                    a_allocated =
                        if a_allocated <=
                               (18446744073709551615 as
                                    libc::c_ulong).wrapping_div(2 as
                                                                    libc::c_int
                                                                    as
                                                                    libc::c_ulong)
                           {
                            a_allocated.wrapping_mul(2 as libc::c_int as
                                                         libc::c_ulong)
                        } else { 18446744073709551615 as libc::c_ulong };
                    if a_allocated <= n_3 {
                        a_allocated = xsum(n_3, 1 as libc::c_int as size_t)
                    }
                    memory_size_0 =
                        if a_allocated <=
                               (18446744073709551615 as
                                    libc::c_ulong).wrapping_div(::std::mem::size_of::<argument>()
                                                                    as
                                                                    libc::c_ulong)
                           {
                            a_allocated.wrapping_mul(::std::mem::size_of::<argument>()
                                                         as libc::c_ulong)
                        } else { 18446744073709551615 as libc::c_ulong };
                    if memory_size_0 == 18446744073709551615 as libc::c_ulong
                       {
                        current_block = 16586880076602670907;
                        break ;
                    }
                    memory_0 =
                        if (*a).arg != (*a).direct_alloc_arg.as_mut_ptr() {
                            realloc((*a).arg as *mut libc::c_void,
                                    memory_size_0)
                        } else { malloc(memory_size_0) } as *mut argument;
                    if memory_0.is_null() {
                        current_block = 16586880076602670907;
                        break ;
                    }
                    if (*a).arg == (*a).direct_alloc_arg.as_mut_ptr() {
                        memcpy(memory_0 as *mut libc::c_void,
                               (*a).arg as *const libc::c_void,
                               (*a).count.wrapping_mul(::std::mem::size_of::<argument>()
                                                           as libc::c_ulong));
                    }
                    (*a).arg = memory_0
                }
                while (*a).count <= n_3 {
                    let fresh4 = (*a).count;
                    (*a).count = (*a).count.wrapping_add(1);
                    (*(*a).arg.offset(fresh4 as isize)).type_0 = TYPE_NONE
                }
                if (*(*a).arg.offset(n_3 as isize)).type_0 as libc::c_uint ==
                       TYPE_NONE as libc::c_int as libc::c_uint {
                    (*(*a).arg.offset(n_3 as isize)).type_0 = TYPE_INT
                } else if (*(*a).arg.offset(n_3 as isize)).type_0 as
                              libc::c_uint !=
                              TYPE_INT as libc::c_int as libc::c_uint {
                    current_block = 9180984893592688305;
                    break ;
                }
            } else {
                let mut precision_length: size_t = 0;
                (*dp).precision_start =
                    cp.offset(-(1 as libc::c_int as isize));
                while *cp as libc::c_int >= '0' as i32 &&
                          *cp as libc::c_int <= '9' as i32 {
                    cp = cp.offset(1)
                }
                (*dp).precision_end = cp;
                precision_length =
                    (*dp).precision_end.offset_from((*dp).precision_start)
                        as libc::c_long as size_t;
                if max_precision_length < precision_length {
                    max_precision_length = precision_length
                }
            }
        }
        let mut type_0: arg_type = TYPE_NONE;
        /* Parse argument type/size specifiers.  */
        let mut flags: libc::c_int = 0 as libc::c_int;
        loop  {
            if *cp as libc::c_int == 'h' as i32 {
                flags |= (1 as libc::c_int) << (flags & 1 as libc::c_int);
                cp = cp.offset(1)
            } else if *cp as libc::c_int == 'L' as i32 {
                flags |= 4 as libc::c_int;
                cp = cp.offset(1)
            } else if *cp as libc::c_int == 'l' as i32 {
                flags += 8 as libc::c_int;
                cp = cp.offset(1)
            } else if *cp as libc::c_int == 'j' as i32 {
                if ::std::mem::size_of::<intmax_t>() as libc::c_ulong >
                       ::std::mem::size_of::<libc::c_long>() as libc::c_ulong
                   {
                    /* intmax_t = long long */
                    flags += 16 as libc::c_int
                } else if ::std::mem::size_of::<intmax_t>() as libc::c_ulong >
                              ::std::mem::size_of::<libc::c_int>() as
                                  libc::c_ulong {
                    /* intmax_t = long */
                    flags += 8 as libc::c_int
                }
                cp = cp.offset(1)
            } else if *cp as libc::c_int == 'z' as i32 ||
                          *cp as libc::c_int == 'Z' as i32 {
                /* 'z' is standardized in ISO C 99, but glibc uses 'Z'
                         because the warning facility in gcc-2.95.2 understands
                         only 'Z' (see gcc-2.95.2/gcc/c-common.c:1784).  */
                if ::std::mem::size_of::<size_t>() as libc::c_ulong >
                       ::std::mem::size_of::<libc::c_long>() as libc::c_ulong
                   {
                    /* size_t = long long */
                    flags += 16 as libc::c_int
                } else if ::std::mem::size_of::<size_t>() as libc::c_ulong >
                              ::std::mem::size_of::<libc::c_int>() as
                                  libc::c_ulong {
                    /* size_t = long */
                    flags += 8 as libc::c_int
                }
                cp = cp.offset(1)
            } else {
                if !(*cp as libc::c_int == 't' as i32) { break ; }
                if ::std::mem::size_of::<ptrdiff_t>() as libc::c_ulong >
                       ::std::mem::size_of::<libc::c_long>() as libc::c_ulong
                   {
                    /* ptrdiff_t = long long */
                    flags += 16 as libc::c_int
                } else if ::std::mem::size_of::<ptrdiff_t>() as libc::c_ulong
                              >
                              ::std::mem::size_of::<libc::c_int>() as
                                  libc::c_ulong {
                    /* ptrdiff_t = long */
                    flags += 8 as libc::c_int
                }
                cp = cp.offset(1)
            }
        }
        /* Read the conversion character.  */
        let fresh5 = cp;
        cp = cp.offset(1);
        c = *fresh5;
        match c as libc::c_int {
            100 | 105 => {
                /* If 'long long' is larger than 'long':  */
                if flags >= 16 as libc::c_int || flags & 4 as libc::c_int != 0
                   {
                    type_0 = TYPE_LONGLONGINT
                } else if flags >= 8 as libc::c_int {
                    type_0 = TYPE_LONGINT
                } else if flags & 2 as libc::c_int != 0 {
                    type_0 = TYPE_SCHAR
                } else if flags & 1 as libc::c_int != 0 {
                    type_0 = TYPE_SHORT
                } else { type_0 = TYPE_INT }
            }
            111 | 117 | 120 | 88 => {
                /* If 'long long' is the same as 'long', we parse "lld" into
                     TYPE_LONGINT.  */
                /* If 'unsigned long long' is larger than 'unsigned long':  */
                if flags >= 16 as libc::c_int || flags & 4 as libc::c_int != 0
                   {
                    type_0 = TYPE_ULONGLONGINT
                } else if flags >= 8 as libc::c_int {
                    type_0 = TYPE_ULONGINT
                } else if flags & 2 as libc::c_int != 0 {
                    type_0 = TYPE_UCHAR
                } else if flags & 1 as libc::c_int != 0 {
                    type_0 = TYPE_USHORT
                } else { type_0 = TYPE_UINT }
            }
            102 | 70 | 101 | 69 | 103 | 71 | 97 | 65 => {
                if flags >= 16 as libc::c_int || flags & 4 as libc::c_int != 0
                   {
                    type_0 = TYPE_LONGDOUBLE
                } else { type_0 = TYPE_DOUBLE }
            }
            99 => {
                if flags >= 8 as libc::c_int {
                    type_0 = TYPE_WIDE_CHAR
                } else { type_0 = TYPE_CHAR }
            }
            67 => { type_0 = TYPE_WIDE_CHAR; c = 'c' as i32 as libc::c_char }
            115 => {
                if flags >= 8 as libc::c_int {
                    type_0 = TYPE_WIDE_STRING
                } else { type_0 = TYPE_STRING }
            }
            83 => {
                type_0 = TYPE_WIDE_STRING;
                c = 's' as i32 as libc::c_char
            }
            112 => { type_0 = TYPE_POINTER }
            110 => {
                /* If 'unsigned long long' is the same as 'unsigned long', we
                     parse "llu" into TYPE_ULONGINT.  */
                /* If 'long long' is larger than 'long':  */
                if flags >= 16 as libc::c_int || flags & 4 as libc::c_int != 0
                   {
                    type_0 = TYPE_COUNT_LONGLONGINT_POINTER
                } else if flags >= 8 as libc::c_int {
                    type_0 = TYPE_COUNT_LONGINT_POINTER
                } else if flags & 2 as libc::c_int != 0 {
                    type_0 = TYPE_COUNT_SCHAR_POINTER
                } else if flags & 1 as libc::c_int != 0 {
                    type_0 = TYPE_COUNT_SHORT_POINTER
                } else { type_0 = TYPE_COUNT_INT_POINTER }
            }
            37 => { type_0 = TYPE_NONE }
            _ => {
                /* If 'long long' is the same as 'long', we parse "lln" into
                     TYPE_COUNT_LONGINT_POINTER.  */
                /* Unknown conversion character.  */
                current_block = 9180984893592688305;
                break ;
            }
        }
        if type_0 as libc::c_uint != TYPE_NONE as libc::c_int as libc::c_uint
           {
            (*dp).arg_index = arg_index;
            if (*dp).arg_index == !(0 as libc::c_int as size_t) {
                let fresh6 = arg_posn;
                arg_posn = arg_posn.wrapping_add(1);
                (*dp).arg_index = fresh6;
                if (*dp).arg_index == !(0 as libc::c_int as size_t) {
                    current_block = 9180984893592688305;
                    break ;
                }
            }
            let mut n_4: size_t = (*dp).arg_index;
            if n_4 >= a_allocated {
                let mut memory_size_1: size_t = 0;
                let mut memory_1: *mut argument = 0 as *mut argument;
                a_allocated =
                    if a_allocated <=
                           (18446744073709551615 as
                                libc::c_ulong).wrapping_div(2 as libc::c_int
                                                                as
                                                                libc::c_ulong)
                       {
                        a_allocated.wrapping_mul(2 as libc::c_int as
                                                     libc::c_ulong)
                    } else { 18446744073709551615 as libc::c_ulong };
                if a_allocated <= n_4 {
                    a_allocated = xsum(n_4, 1 as libc::c_int as size_t)
                }
                memory_size_1 =
                    if a_allocated <=
                           (18446744073709551615 as
                                libc::c_ulong).wrapping_div(::std::mem::size_of::<argument>()
                                                                as
                                                                libc::c_ulong)
                       {
                        a_allocated.wrapping_mul(::std::mem::size_of::<argument>()
                                                     as libc::c_ulong)
                    } else { 18446744073709551615 as libc::c_ulong };
                if memory_size_1 == 18446744073709551615 as libc::c_ulong {
                    current_block = 16586880076602670907;
                    break ;
                }
                memory_1 =
                    if (*a).arg != (*a).direct_alloc_arg.as_mut_ptr() {
                        realloc((*a).arg as *mut libc::c_void, memory_size_1)
                    } else { malloc(memory_size_1) } as *mut argument;
                if memory_1.is_null() {
                    current_block = 16586880076602670907;
                    break ;
                }
                if (*a).arg == (*a).direct_alloc_arg.as_mut_ptr() {
                    memcpy(memory_1 as *mut libc::c_void,
                           (*a).arg as *const libc::c_void,
                           (*a).count.wrapping_mul(::std::mem::size_of::<argument>()
                                                       as libc::c_ulong));
                }
                (*a).arg = memory_1
            }
            while (*a).count <= n_4 {
                let fresh7 = (*a).count;
                (*a).count = (*a).count.wrapping_add(1);
                (*(*a).arg.offset(fresh7 as isize)).type_0 = TYPE_NONE
            }
            if (*(*a).arg.offset(n_4 as isize)).type_0 as libc::c_uint ==
                   TYPE_NONE as libc::c_int as libc::c_uint {
                (*(*a).arg.offset(n_4 as isize)).type_0 = type_0
            } else if (*(*a).arg.offset(n_4 as isize)).type_0 as libc::c_uint
                          != type_0 as libc::c_uint {
                current_block = 9180984893592688305;
                break ;
            }
        }
        (*dp).conversion = c;
        (*dp).dir_end = cp;
        (*d).count = (*d).count.wrapping_add(1);
        if !((*d).count >= d_allocated) { continue ; }
        let mut memory_size_2: size_t = 0;
        let mut memory_2: *mut char_directive = 0 as *mut char_directive;
        d_allocated =
            if d_allocated <=
                   (18446744073709551615 as
                        libc::c_ulong).wrapping_div(2 as libc::c_int as
                                                        libc::c_ulong) {
                d_allocated.wrapping_mul(2 as libc::c_int as libc::c_ulong)
            } else { 18446744073709551615 as libc::c_ulong };
        memory_size_2 =
            if d_allocated <=
                   (18446744073709551615 as
                        libc::c_ulong).wrapping_div(::std::mem::size_of::<char_directive>()
                                                        as libc::c_ulong) {
                d_allocated.wrapping_mul(::std::mem::size_of::<char_directive>()
                                             as libc::c_ulong)
            } else { 18446744073709551615 as libc::c_ulong };
        if memory_size_2 == 18446744073709551615 as libc::c_ulong {
            /* Overflow, would lead to out of memory.  */
            current_block = 16586880076602670907;
            break ;
        } else {
            memory_2 =
                if (*d).dir != (*d).direct_alloc_dir.as_mut_ptr() {
                    realloc((*d).dir as *mut libc::c_void, memory_size_2)
                } else { malloc(memory_size_2) } as *mut char_directive;
            if memory_2.is_null() {
                current_block = 16586880076602670907;
                break ;
            }
            if (*d).dir == (*d).direct_alloc_dir.as_mut_ptr() {
                memcpy(memory_2 as *mut libc::c_void,
                       (*d).dir as *const libc::c_void,
                       (*d).count.wrapping_mul(::std::mem::size_of::<char_directive>()
                                                   as libc::c_ulong));
            }
            (*d).dir = memory_2
        }
    }
    match current_block {
        16586880076602670907 =>
        /* Out of memory.  */
        {
            if (*a).arg != (*a).direct_alloc_arg.as_mut_ptr() {
                rpl_free((*a).arg as *mut libc::c_void);
            }
            if (*d).dir != (*d).direct_alloc_dir.as_mut_ptr() {
                rpl_free((*d).dir as *mut libc::c_void);
            }
            *__errno_location() = 12 as libc::c_int;
            return -(1 as libc::c_int)
        }
        9180984893592688305 =>
        /* arg_posn wrapped around.  */
        {
            if (*a).arg != (*a).direct_alloc_arg.as_mut_ptr() {
                rpl_free((*a).arg as *mut libc::c_void);
            }
            if (*d).dir != (*d).direct_alloc_dir.as_mut_ptr() {
                rpl_free((*d).dir as *mut libc::c_void);
            }
            *__errno_location() = 22 as libc::c_int;
            return -(1 as libc::c_int)
        }
        _ => {
            let ref mut fresh8 =
                (*(*d).dir.offset((*d).count as isize)).dir_start;
            *fresh8 = cp;
            (*d).max_width_length = max_width_length;
            (*d).max_precision_length = max_precision_length;
            return 0 as libc::c_int
        }
    };
}
