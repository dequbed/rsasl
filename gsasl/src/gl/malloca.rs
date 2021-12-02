use ::libc;
extern "C" {
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn abort() -> !;
    #[no_mangle]
    fn rpl_free(ptr: *mut libc::c_void);
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type uintptr_t = libc::c_ulong;
/* Safe automatic memory allocation.
   Copyright (C) 2003, 2006-2007, 2009-2021 Free Software Foundation, Inc.
   Written by Bruno Haible <bruno@clisp.org>, 2003, 2018.

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
/* The speed critical point in this file is freea() applied to an alloca()
   result: it must be fast, to match the speed of alloca().  The speed of
   mmalloca() and freea() in the other case are not critical, because they
   are only invoked for big memory sizes.
   Here we use a bit in the address as an indicator, an idea by Ondřej Bílka.
   malloca() can return three types of pointers:
     - Pointers ≡ 0 mod 2*sa_alignment_max come from stack allocation.
     - Pointers ≡ sa_alignment_max mod 2*sa_alignment_max come from heap
       allocation.
     - NULL comes from a failed heap allocation.  */
/* Type for holding very small pointer differences.  */
pub type small_t = libc::c_uchar;
pub const sa_alignment_max: C2RustUnnamed = 16;
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
/* nmalloca(N,S) is an overflow-safe variant of malloca (N * S).
   It allocates an array of N objects, each with S bytes of memory,
   on the stack.  N and S should be nonnegative and free of side effects.
   The array must be freed using freea() before the function returns.  */
/* ------------------- Auxiliary, non-public definitions ------------------- */
/* Determine the alignment of a type at compile time.  */
pub type C2RustUnnamed = libc::c_uint;
pub const sa_alignment_longdouble: C2RustUnnamed = 16;
pub const sa_alignment_longlong: C2RustUnnamed = 8;
pub const sa_alignment_double: C2RustUnnamed = 8;
/* The desired alignment of memory allocations is the maximum alignment
   among all elementary types.  */
pub const sa_alignment_long: C2RustUnnamed = 8;
/* malloca(N) is a safe variant of alloca(N).  It allocates N bytes of
   memory allocated on the stack, that must be freed using freea() before
   the function returns.  Upon failure, it returns NULL.  */
#[no_mangle]
pub unsafe extern "C" fn mmalloca(mut n: size_t) -> *mut libc::c_void {
    /* Allocate one more word, used to determine the address to pass to freea(),
     and room for the alignment ≡ sa_alignment_max mod 2*sa_alignment_max.  */
    let mut alignment2_mask: uintptr_t =
        (2 as libc::c_int * sa_alignment_max as libc::c_int -
             1 as libc::c_int) as uintptr_t;
    let mut plus: libc::c_int =
        (::std::mem::size_of::<small_t>() as
             libc::c_ulong).wrapping_add(alignment2_mask) as libc::c_int;
    let mut nplus: idx_t = 0;
    let (fresh0, fresh1) = n.overflowing_add(plus as u64);
    *(&mut nplus as *mut idx_t) = fresh0 as i64;
    if !fresh1 &&
           !(1 as libc::c_int != 0 as libc::c_int &&
                 (if (9223372036854775807 as libc::c_long as libc::c_ulong) <
                         18446744073709551615 as libc::c_ulong {
                      9223372036854775807 as libc::c_long as libc::c_ulong
                  } else {
                      (18446744073709551615 as
                           libc::c_ulong).wrapping_sub(1 as libc::c_int as
                                                           libc::c_ulong)
                  }).wrapping_div(1 as libc::c_int as libc::c_ulong) <
                     nplus as libc::c_ulong) {
        let mut mem: *mut libc::c_char =
            malloc(nplus as libc::c_ulong) as *mut libc::c_char;
        if !mem.is_null() {
            let mut umem: uintptr_t = mem as uintptr_t;
            let mut umemplus: uintptr_t = 0;
            /* The INT_ADD_WRAPV avoids signed integer overflow on
             theoretical platforms where UINTPTR_MAX <= INT_MAX.  */
            let (fresh2, fresh3) =
                umem.overflowing_add((::std::mem::size_of::<small_t>() as
                                          libc::c_ulong).wrapping_add(sa_alignment_max
                                                                          as
                                                                          libc::c_int
                                                                          as
                                                                          libc::c_ulong).wrapping_sub(1
                                                                                                          as
                                                                                                          libc::c_int
                                                                                                          as
                                                                                                          libc::c_ulong));
            *&mut umemplus = fresh2;
            let mut offset: idx_t =
                (umemplus &
                     !alignment2_mask).wrapping_add(sa_alignment_max as
                                                        libc::c_int as
                                                        libc::c_ulong).wrapping_sub(umem)
                    as idx_t;
            let mut vp: *mut libc::c_void =
                mem.offset(offset as isize) as *mut libc::c_void;
            let mut p: *mut small_t = vp as *mut small_t;
            /* Here p >= mem + sizeof (small_t),
             and p <= mem + sizeof (small_t) + 2 * sa_alignment_max - 1
             hence p + n <= mem + nplus.
             So, the memory range [p, p+n) lies in the allocated memory range
             [mem, mem + nplus).  */
            *p.offset(-(1 as libc::c_int) as isize) = offset as small_t;
            /* p ≡ sa_alignment_max mod 2*sa_alignment_max.  */
            return p as *mut libc::c_void
        }
    }
    /* Out of memory.  */
    return 0 as *mut libc::c_void;
}
/* Safe automatic memory allocation.
   Copyright (C) 2003-2007, 2009-2021 Free Software Foundation, Inc.
   Written by Bruno Haible <bruno@clisp.org>, 2003.

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
/* safe_alloca(N) is equivalent to alloca(N) when it is safe to call
   alloca(N); otherwise it returns NULL.  It either returns N bytes of
   memory allocated on the stack, that lasts until the function returns,
   or NULL.
   Use of safe_alloca should be avoided:
     - inside arguments of function calls - undefined behaviour,
     - in inline functions - the allocation may actually last until the
       calling function returns.
*/
/* The OS usually guarantees only one guard page at the bottom of the stack,
   and a page size can be as small as 4096 bytes.  So we cannot safely
   allocate anything larger than 4096 bytes.  Also care for the possibility
   of a few compiler-allocated temporary stack slots.
   This must be a macro, not a function.  */
/* Free a block of memory allocated through malloca().  */
#[no_mangle]
pub unsafe extern "C" fn freea(mut p: *mut libc::c_void) {
    /* Check argument.  */
    if p as uintptr_t &
           (sa_alignment_max as libc::c_int - 1 as libc::c_int) as
               libc::c_ulong != 0 {
        /* p was not the result of a malloca() call.  Invalid argument.  */
        abort();
    }
    /* Determine whether p was a non-NULL pointer returned by mmalloca().  */
    if p as uintptr_t & sa_alignment_max as libc::c_int as libc::c_ulong != 0
       {
        let mut mem: *mut libc::c_void =
            (p as
                 *mut libc::c_char).offset(-(*(p as
                                                   *mut small_t).offset(-(1 as
                                                                              libc::c_int)
                                                                            as
                                                                            isize)
                                                 as libc::c_int as isize)) as
                *mut libc::c_void;
        rpl_free(mem);
    };
}
/*
 * Hey Emacs!
 * Local Variables:
 * coding: utf-8
 * End:
 */
