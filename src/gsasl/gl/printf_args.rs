use ::libc;
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
/* Fetch the arguments, putting them into a. */
/* Decomposed printf argument list.
   Copyright (C) 1999, 2002-2003, 2005-2007, 2009-2021 Free Software
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
     PRINTF_FETCHARGS   Name of the function to be defined.
     STATIC             Set to 'static' to declare the function static.  */
/* Specification.  */
#[no_mangle]
pub unsafe fn printf_fetchargs(mut args: ::std::ffi::VaList,
                                          mut a: *mut arguments)
 -> libc::c_int {
    let mut i: size_t = 0; /*signed char*/
    let mut ap: *mut argument = 0 as *mut argument; /*unsigned char*/
    i = 0 as libc::c_int as size_t; /*short*/
    ap =
        &mut *(*a).arg.offset(0 as libc::c_int as isize) as
            *mut argument; /*unsigned short*/
    while i < (*a).count {
        match (*ap).type_0 as libc::c_uint {
            1 => {
                (*ap).a.a_schar = args.arg::<libc::c_int>() as libc::c_schar
            }
            2 => {
                (*ap).a.a_uchar = args.arg::<libc::c_int>() as libc::c_uchar
            }
            3 => {
                (*ap).a.a_short = args.arg::<libc::c_int>() as libc::c_short
            }
            4 => {
                (*ap).a.a_ushort = args.arg::<libc::c_int>() as libc::c_ushort
            }
            5 => { (*ap).a.a_int = args.arg::<libc::c_int>() }
            6 => { (*ap).a.a_uint = args.arg::<libc::c_uint>() }
            7 => { (*ap).a.a_longint = args.arg::<libc::c_long>() }
            8 => { (*ap).a.a_ulongint = args.arg::<libc::c_ulong>() }
            9 => { (*ap).a.a_longlongint = args.arg::<libc::c_longlong>() }
            10 => { (*ap).a.a_ulonglongint = args.arg::<libc::c_ulonglong>() }
            11 => { (*ap).a.a_double = args.arg::<libc::c_double>() }
            13 => { (*ap).a.a_char = args.arg::<libc::c_int>() }
            14 => {
                /* Although ISO C 99 7.24.1.(2) says that wint_t is "unchanged by
           default argument promotions", this is not the case in mingw32,
           where wint_t is 'unsigned short'.  */
                (*ap).a.a_wide_char =
                    if (::std::mem::size_of::<wint_t>() as libc::c_ulong) <
                           ::std::mem::size_of::<libc::c_int>() as
                               libc::c_ulong {
                        args.arg::<libc::c_int>() as wint_t
                    } else { args.arg::<wint_t>() }
            }
            15 => {
                (*ap).a.a_string = args.arg::<*const libc::c_char>();
                /* A null pointer is an invalid argument for "%s", but in practice
           it occurs quite frequently in printf statements that produce
           debug output.  Use a fallback in this case.  */
                if (*ap).a.a_string.is_null() {
                    (*ap).a.a_string =
                        b"(NULL)\x00" as *const u8 as *const libc::c_char
                }
            }
            16 => {
                (*ap).a.a_wide_string = args.arg::<*const wchar_t>();
                /* A null pointer is an invalid argument for "%ls", but in practice
           it occurs quite frequently in printf statements that produce
           debug output.  Use a fallback in this case.  */
                if (*ap).a.a_wide_string.is_null() {
                    static mut wide_null_string: [wchar_t; 7] =
                        ['(' as i32, 'N' as i32, 'U' as i32, 'L' as i32,
                         'L' as i32, ')' as i32, 0 as libc::c_int];
                    (*ap).a.a_wide_string = wide_null_string.as_ptr()
                }
            }
            17 => { (*ap).a.a_pointer = args.arg::<*mut libc::c_void>() }
            18 => {
                (*ap).a.a_count_schar_pointer =
                    args.arg::<*mut libc::c_schar>()
            }
            19 => {
                (*ap).a.a_count_short_pointer =
                    args.arg::<*mut libc::c_short>()
            }
            20 => {
                (*ap).a.a_count_int_pointer = args.arg::<*mut libc::c_int>()
            }
            21 => {
                (*ap).a.a_count_longint_pointer =
                    args.arg::<*mut libc::c_long>()
            }
            22 => {
                (*ap).a.a_count_longlongint_pointer =
                    args.arg::<*mut libc::c_longlong>()
            }
            _ => {
                /* Unknown type.  */
                return -(1 as libc::c_int)
            }
        }
        i = i.wrapping_add(1);
        ap = ap.offset(1)
    }
    return 0 as libc::c_int;
}
