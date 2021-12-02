use ::libc;
extern "C" {
    #[no_mangle]
    fn __errno_location() -> *mut libc::c_int;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn reallocarray(__ptr: *mut libc::c_void, __nmemb: size_t, __size: size_t)
     -> *mut libc::c_void;
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
/* A type for indices and sizes.
   Copyright (C) 2020-2021 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */
/* Get ptrdiff_t.  */
/* Get PTRDIFF_MAX.  */
/* The type 'idx_t' holds an (array) index or an (object) size.
   Its implementation promotes to a signed integer type,
   which can hold the values
     0..2^63-1 (on 64-bit platforms) or
     0..2^31-1 (on 32-bit platforms).

   Why a signed integer type?

     * Security: Signed types can be checked for overflow via
       '-fsanitize=undefined', but unsigned types cannot.

     * Comparisons without surprises: ISO C99 § 6.3.1.8 specifies a few
       surprising results for comparisons, such as

           (int) -3 < (unsigned long) 7  =>  false
           (int) -3 < (unsigned int) 7   =>  false
       and on 32-bit machines:
           (long) -3 < (unsigned int) 7  =>  false

       This is surprising because the natural comparison order is by
       value in the realm of infinite-precision signed integers (ℤ).

       The best way to get rid of such surprises is to use signed types
       for numerical integer values, and use unsigned types only for
       bit masks and enums.

   Why not use 'size_t' directly?

     * Because 'size_t' is an unsigned type, and a signed type is better.
       See above.

   Why not use 'ssize_t'?

     * 'ptrdiff_t' is more portable; it is standardized by ISO C
       whereas 'ssize_t' is standardized only by POSIX.

     * 'ssize_t' is not required to be as wide as 'size_t', and some
       now-obsolete POSIX platforms had 'size_t' wider than 'ssize_t'.

     * Conversely, some now-obsolete platforms had 'ptrdiff_t' wider
       than 'size_t', which can be a win and conforms to POSIX.

   Won't this cause a problem with objects larger than PTRDIFF_MAX?

     * Typical modern or large platforms do not allocate such objects,
       so this is not much of a problem in practice; for example, you
       can safely write 'idx_t len = strlen (s);'.  To port to older
       small platforms where allocations larger than PTRDIFF_MAX could
       in theory be a problem, you can use Gnulib's ialloc module, or
       functions like ximalloc in Gnulib's xalloc module.

   Why not use 'ptrdiff_t' directly?

     * Maintainability: When reading and modifying code, it helps to know that
       a certain variable cannot have negative values.  For example, when you
       have a loop

         int n = ...;
         for (int i = 0; i < n; i++) ...

       or

         ptrdiff_t n = ...;
         for (ptrdiff_t i = 0; i < n; i++) ...

       you have to ask yourself "what if n < 0?".  Whereas in

         idx_t n = ...;
         for (idx_t i = 0; i < n; i++) ...

       you know that this case cannot happen.

       Similarly, when a programmer writes

         idx_t = ptr2 - ptr1;

       there is an implied assertion that ptr1 and ptr2 point into the same
       object and that ptr1 <= ptr2.

     * Being future-proof: In the future, range types (integers which are
       constrained to a certain range of values) may be added to C compilers
       or to the C standard.  Several programming languages (Ada, Haskell,
       Common Lisp, Pascal) already have range types.  Such range types may
       help producing good code and good warnings.  The type 'idx_t' could
       then be typedef'ed to a range type that is signed after promotion.  */
/* In the future, idx_t could be typedef'ed to a signed range type.
   The clang "extended integer types", supported in Clang 11 or newer
   <https://clang.llvm.org/docs/LanguageExtensions.html#extended-integer-types>,
   are a special case of range types.  However, these types don't support binary
   operators with plain integer types (e.g. expressions such as x > 1).
   Therefore, they don't behave like signed types (and not like unsigned types
   either).  So, we cannot use them here.  */
/* Use the signed type 'ptrdiff_t'.  */
/* Note: ISO C does not mandate that 'size_t' and 'ptrdiff_t' have the same
   size, but it is so on all platforms we have seen since 1990.  */
pub type idx_t = ptrdiff_t;
/* ialloc.h -- malloc with idx_t rather than size_t

   Copyright 2021 Free Software Foundation, Inc.

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
/*_GL_ATTRIBUTE_DEALLOC_FREE*/
/*_GL_ATTRIBUTE_DEALLOC_FREE*/
/* Work around GNU realloc glitch by treating a zero size as if it
     were 1, so that returning NULL is equivalent to failing.  */
/*_GL_ATTRIBUTE_DEALLOC_FREE*/
#[no_mangle]
#[inline]
pub unsafe extern "C" fn ireallocarray(mut p: *mut libc::c_void, mut n: idx_t,
                                       mut s: idx_t) -> *mut libc::c_void {
    /* Work around GNU reallocarray glitch by treating a zero size as if
     it were 1, so that returning NULL is equivalent to failing.  */
    if n == 0 as libc::c_int as libc::c_long ||
           s == 0 as libc::c_int as libc::c_long {
        s = 1 as libc::c_int as idx_t;
        n = s
    }
    return if n as libc::c_ulong <= 18446744073709551615 as libc::c_ulong &&
                  s as libc::c_ulong <= 18446744073709551615 as libc::c_ulong
              {
               reallocarray(p, n as size_t, s as size_t)
           } else { _gl_alloc_nomem() };
}
#[no_mangle]
#[inline]
pub unsafe extern "C" fn icalloc(mut n: idx_t, mut s: idx_t)
 -> *mut libc::c_void {
    if (18446744073709551615 as libc::c_ulong) < n as libc::c_ulong {
        if s != 0 as libc::c_int as libc::c_long { return _gl_alloc_nomem() }
        n = 0 as libc::c_int as idx_t
    }
    if (18446744073709551615 as libc::c_ulong) < s as libc::c_ulong {
        if n != 0 as libc::c_int as libc::c_long { return _gl_alloc_nomem() }
        s = 0 as libc::c_int as idx_t
    }
    return calloc(n as libc::c_ulong, s as libc::c_ulong);
}
#[no_mangle]
#[inline]
pub unsafe extern "C" fn irealloc(mut p: *mut libc::c_void, mut s: idx_t)
 -> *mut libc::c_void {
    return if s as libc::c_ulong <= 18446744073709551615 as libc::c_ulong {
               realloc(p,
                       (s | (s == 0) as libc::c_int as libc::c_long) as
                           libc::c_ulong)
           } else { _gl_alloc_nomem() };
}
#[no_mangle]
#[inline]
pub unsafe extern "C" fn imalloc(mut s: idx_t) -> *mut libc::c_void {
    return if s as libc::c_ulong <= 18446744073709551615 as libc::c_ulong {
               malloc(s as libc::c_ulong)
           } else { _gl_alloc_nomem() };
}
#[no_mangle]
#[cold]
#[inline]
pub unsafe extern "C" fn _gl_alloc_nomem() -> *mut libc::c_void {
    *__errno_location() = 12 as libc::c_int;
    return 0 as *mut libc::c_void;
}
/* malloc with idx_t rather than size_t

   Copyright 2021 Free Software Foundation, Inc.

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
