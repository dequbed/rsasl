use std::mem::ManuallyDrop;
use std::ptr::slice_from_raw_parts;
use ::libc;
use base64::CharacterSet;
use libc::{size_t, ptrdiff_t};
use crate::gsasl::consts::*;
use crate::gsasl::gl::base64::base64_decode_alloc_ctx;
use crate::gsasl::mechtools::{_gsasl_hex_decode, _gsasl_hex_encode, _gsasl_hex_p};

extern "C" {
    fn strlen(_: *const libc::c_char) -> size_t;
    fn malloc(_: size_t) -> *mut libc::c_void;
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct base64_decode_context {
    pub i: libc::c_int,
    pub buf: [libc::c_char; 4],
}
/* base64.c --- Base64 encoding/decoding functions.
 * Copyright (C) 2002-2021 Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License License along with GNU SASL Library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */
/* *
 * gsasl_base64_to:
 * @in: input byte array.
 * @inlen: size of input byte array.
 * @out: pointer to newly allocated base64-encoded string.
 * @outlen: pointer to size of newly allocated base64-encoded string.
 *
 * Encode data as base64.  The @out string is zero terminated, and
 * @outlen holds the length excluding the terminating zero.  The @out
 * buffer must be deallocated by the caller.
 *
 * Return value: Returns %GSASL_OK on success, or %GSASL_MALLOC_ERROR
 *   if input was too large or memory allocation fail.
 *
 * Since: 0.2.2
 **/
#[no_mangle]
pub unsafe fn gsasl_base64_to(mut in_0: *const libc::c_char,
                                         mut inlen: size_t,
                                         mut out: *mut *mut libc::c_char,
                                         mut outlen: *mut size_t)
 -> libc::c_int {
    if in_0.is_null() || inlen == 0 || out.is_null() {
        if !out.is_null() {
            *out = std::ptr::null_mut();
        }
        if !outlen.is_null() {
            *outlen = 0;
        }
        return GSASL_OK as libc::c_int;
    }

    let maxlen = inlen * 4 / 3 + 4;
    // make sure we'll have a slice big enough for base64 + padding
    let mut buf = ManuallyDrop::new(Vec::with_capacity(maxlen + 1));
    buf.set_len(maxlen);
    let input = std::slice::from_raw_parts(in_0.cast(), inlen);
    let config = base64::Config::new(CharacterSet::Standard, true);
    let len = base64::encode_config_slice(input, config, &mut buf[0..maxlen]);
    buf.set_len(len);
    buf.push(b'\0');

    if !outlen.is_null() {
        *outlen = buf.len();
    }
    *out = buf.as_mut_ptr().cast();

    return GSASL_OK as libc::c_int;
}
/* *
 * gsasl_base64_from:
 * @in: input byte array
 * @inlen: size of input byte array
 * @out: pointer to newly allocated output byte array
 * @outlen: pointer to size of newly allocated output byte array
 *
 * Decode Base64 data.  The @out buffer must be deallocated by the
 * caller.
 *
 * Return value: Returns %GSASL_OK on success, %GSASL_BASE64_ERROR if
 *   input was invalid, and %GSASL_MALLOC_ERROR on memory allocation
 *   errors.
 *
 * Since: 0.2.2
 **/
#[no_mangle]
pub unsafe fn gsasl_base64_from(mut in_0: *const libc::c_char,
                                mut inlen: size_t,
                                mut out: *mut *mut libc::c_char,
                                mut outlen: *mut size_t)
 -> libc::c_int {
    if !out.is_null() {
        *out = std::ptr::null_mut();
    }
    if !outlen.is_null() {
        *outlen = 0;
    }
    if in_0.is_null() || inlen == 0 || out.is_null() {
        return GSASL_OK as libc::c_int;
    }

    let maxlen = inlen * 3 / 4 + 3;
    // make sure we'll have a slice big enough for base64 + padding
    let mut output = ManuallyDrop::new(Vec::with_capacity(maxlen + 1));
    output.set_len(maxlen + 1);
    let input = std::slice::from_raw_parts(in_0.cast(), inlen);

    print!("Input: ");
    for c in input.iter().map(|c| *c as char) {
        print!("{}", c);
    }
    print!("\n");

    let config = base64::Config::new(CharacterSet::Standard, true);
    match base64::decode_config_slice(input, config, &mut output[..]) {
        Ok(len) => {
            output.set_len(len);
        },
        Err(e) => {
            println!("{:?}", e);
            return GSASL_BASE64_ERROR as libc::c_int
        },
    }
    output.push(b'\0');
    println!("{:?}", output);

    if !outlen.is_null() {
        *outlen = output.len();
    }

    *out = output.as_mut_ptr().cast();

    return GSASL_OK as libc::c_int;
}