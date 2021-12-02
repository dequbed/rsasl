use ::libc;
extern "C" {
    #[no_mangle]
    fn vasnprintf(resultbuf: *mut libc::c_char, lengthp: *mut size_t,
                  format: *const libc::c_char, args: ::std::ffi::VaList)
     -> *mut libc::c_char;
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type va_list = __builtin_va_list;
pub type size_t = libc::c_ulong;
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
/* Formatted output to strings.
   Copyright (C) 1999, 2002, 2006, 2009-2021 Free Software Foundation, Inc.

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
#[no_mangle]
pub unsafe extern "C" fn asnprintf(mut resultbuf: *mut libc::c_char,
                                   mut lengthp: *mut size_t,
                                   mut format: *const libc::c_char,
                                   mut args: ...) -> *mut libc::c_char {
    let mut args_0: ::std::ffi::VaListImpl;
    let mut result: *mut libc::c_char = 0 as *mut libc::c_char;
    args_0 = args.clone();
    result = vasnprintf(resultbuf, lengthp, format, args_0.as_va_list());
    return result;
}
