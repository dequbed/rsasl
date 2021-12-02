use ::libc;
use libc::size_t;
extern "C" {

    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: size_t) -> libc::c_int;

    fn memchr(_: *const libc::c_void, _: libc::c_int, _: size_t) -> *mut libc::c_void;
}
/* getsubopt.c --- Parse comma separate list into words, DIGEST-MD5 style.
 * Copyright (C) 2002-2021 Simon Josefsson
 * Copyright (C) 1996, 1997, 1999 Free Software Foundation, Inc.
 * From the GNU C Library, under GNU LGPL version 2.1.
 * Contributed by Ulrich Drepper <drepper@cygnus.com>, 1996.
 * Modified for Libgsasl by Simon Josefsson <simon@josefsson.org>
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
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */
/* Get prototypes. */
/* Get memchr and memcmp. */
/* Parse comma separated suboption from *OPTIONP and match against
   strings in TOKENS.  If found return index and set *VALUEP to
   optional value introduced by an equal sign.  If the suboption is
   not part of TOKENS return in *VALUEP beginning of unknown
   suboption.  On exit *OPTIONP is set to the beginning of the next
   token or at the terminating NUL character.

   This function is NOT identical to standard getsubopt! */
#[no_mangle]
pub unsafe extern "C" fn digest_md5_getsubopt(mut optionp:
                                                  *mut *mut libc::c_char,
                                              mut tokens:
                                                  *const *const libc::c_char,
                                              mut valuep:
                                                  *mut *mut libc::c_char)
 -> libc::c_int {
    let mut endp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut vstart: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cnt: libc::c_int = 0;
    let mut inside_quote: libc::c_int = 0 as libc::c_int;
    if **optionp as libc::c_int == '\u{0}' as i32 {
        return -(1 as libc::c_int)
    }
    /* Find end of next token.  */
    endp = *optionp;
    while *endp as libc::c_int != '\u{0}' as i32 &&
              (inside_quote != 0 ||
                   inside_quote == 0 && *endp as libc::c_int != ',' as i32) {
        if *endp as libc::c_int == '\"' as i32 {
            inside_quote = (inside_quote == 0) as libc::c_int
        }
        endp = endp.offset(1)
    }
    /* Find start of value.  */
    vstart =
        memchr(*optionp as *const libc::c_void, '=' as i32,
               endp.offset_from(*optionp) as size_t) as *mut libc::c_char;
    if vstart.is_null() { vstart = endp }
    /* Try to match the characters between *OPTIONP and VSTART against
     one of the TOKENS.  */
    cnt = 0 as libc::c_int;
    while !(*tokens.offset(cnt as isize)).is_null() {
        if memcmp(*optionp as *const libc::c_void,
                  *tokens.offset(cnt as isize) as *const libc::c_void,
                  vstart.offset_from(*optionp) as size_t) == 0
            &&
               *(*tokens.offset(cnt as
                                    isize)).offset(vstart.offset_from(*optionp)
                                                       as libc::c_long as
                                                       isize) as libc::c_int
                   == '\u{0}' as i32 {
            /* We found the current option in TOKENS.  */
            *valuep =
                if vstart != endp {
                    vstart.offset(1 as libc::c_int as isize)
                } else { 0 as *mut libc::c_char };
            while !(*valuep).is_null() &&
                      (**valuep as libc::c_int == ' ' as i32 ||
                           **valuep as libc::c_int == '\t' as i32 ||
                           **valuep as libc::c_int == '\r' as i32 ||
                           **valuep as libc::c_int == '\n' as i32 ||
                           **valuep as libc::c_int == '\"' as i32) {
                *valuep = (*valuep).offset(1)
            }
            if *endp as libc::c_int != '\u{0}' as i32 {
                *endp = '\u{0}' as i32 as libc::c_char;
                *optionp = endp.offset(1 as libc::c_int as isize)
            } else { *optionp = endp }
            endp = endp.offset(-1);
            while *endp as libc::c_int == ' ' as i32 ||
                      *endp as libc::c_int == '\t' as i32 ||
                      *endp as libc::c_int == '\r' as i32 ||
                      *endp as libc::c_int == '\n' as i32 ||
                      *endp as libc::c_int == '\"' as i32 {
                let fresh0 = endp;
                endp = endp.offset(-1);
                *fresh0 = '\u{0}' as i32 as libc::c_char
            }
            while **optionp as libc::c_int == ' ' as i32 ||
                      **optionp as libc::c_int == '\t' as i32 ||
                      **optionp as libc::c_int == '\r' as i32 ||
                      **optionp as libc::c_int == '\n' as i32 {
                *optionp = (*optionp).offset(1)
            }
            return cnt
        }
        cnt += 1
    }
    /* The current suboption does not match any option.  */
    *valuep = *optionp;
    if *endp as libc::c_int != '\u{0}' as i32 {
        let fresh1 = endp;
        endp = endp.offset(1);
        *fresh1 = '\u{0}' as i32 as libc::c_char
    }
    *optionp = endp;
    while **optionp as libc::c_int == ' ' as i32 ||
              **optionp as libc::c_int == '\t' as i32 ||
              **optionp as libc::c_int == '\r' as i32 ||
              **optionp as libc::c_int == '\n' as i32 {
        *optionp = (*optionp).offset(1)
    }
    return -(1 as libc::c_int);
}
