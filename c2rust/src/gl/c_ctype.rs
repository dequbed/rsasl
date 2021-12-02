use ::libc;
/* Character handling in C locale.

   These functions work like the corresponding functions in <ctype.h>,
   except that they have the C (POSIX) locale hardwired, whereas the
   <ctype.h> functions' behaviour depends on the current locale set via
   setlocale.

   Copyright (C) 2000-2003, 2006, 2008-2021 Free Software Foundation, Inc.

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
/* The functions defined in this file assume the "C" locale and a character
   set without diacritics (ASCII-US or EBCDIC-US or something like that).
   Even if the "C" locale on a particular system is an extension of the ASCII
   character set (like on BeOS, where it is UTF-8, or on AmigaOS, where it
   is ISO-8859-1), the functions in this file recognize only the ASCII
   characters.  */
/* The character set is ASCII or one of its variants or extensions, not EBCDIC.
   Testing the value of '\n' and '\r' is not relevant.  */
/* Cases for control characters.  */
/* ASCII control characters other than those with \-letter escapes.  */
/* Cases for lowercase hex letters, and lowercase letters, all offset by N.  */
/* Cases for hex letters, digits, lower, punct, and upper.  */
/* Function definitions.  */
/* Unlike the functions in <ctype.h>, which require an argument in the range
   of the 'unsigned char' type, the functions here operate on values that are
   in the 'unsigned char' range or in the 'char' range.  In other words,
   when you have a 'char' value, you need to cast it before using it as
   argument to a <ctype.h> function:

         const char *s = ...;
         if (isalpha ((unsigned char) *s)) ...

   but you don't need to cast it for the functions defined in this file:

         const char *s = ...;
         if (c_isalpha (*s)) ...
 */
#[no_mangle]
#[inline]
#[linkage = "external"]
pub unsafe extern "C" fn c_isalnum(mut c: libc::c_int) -> bool {
    match c {
        48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 | 57 | 97 | 98 | 99 | 100 |
        101 | 102 | 103 | 104 | 105 | 106 | 107 | 108 | 109 | 110 | 111 | 112
        | 113 | 114 | 115 | 116 | 117 | 118 | 119 | 120 | 121 | 122 | 65 | 66
        | 67 | 68 | 69 | 70 | 71 | 72 | 73 | 74 | 75 | 76 | 77 | 78 | 79 | 80
        | 81 | 82 | 83 | 84 | 85 | 86 | 87 | 88 | 89 | 90 => {
            return 1 as libc::c_int != 0
        }
        _ => { return 0 as libc::c_int != 0 }
    };
}
#[no_mangle]
#[inline]
#[linkage = "external"]
pub unsafe extern "C" fn c_isalpha(mut c: libc::c_int) -> bool {
    match c {
        97 | 98 | 99 | 100 | 101 | 102 | 103 | 104 | 105 | 106 | 107 | 108 |
        109 | 110 | 111 | 112 | 113 | 114 | 115 | 116 | 117 | 118 | 119 | 120
        | 121 | 122 | 65 | 66 | 67 | 68 | 69 | 70 | 71 | 72 | 73 | 74 | 75 |
        76 | 77 | 78 | 79 | 80 | 81 | 82 | 83 | 84 | 85 | 86 | 87 | 88 | 89 |
        90 => {
            return 1 as libc::c_int != 0
        }
        _ => { return 0 as libc::c_int != 0 }
    };
}
/* The function isascii is not locale dependent.
   Its use in EBCDIC is questionable. */
#[no_mangle]
#[inline]
#[linkage = "external"]
pub unsafe extern "C" fn c_isascii(mut c: libc::c_int) -> bool {
    match c {
        32 | 7 | 8 | 12 | 10 | 13 | 9 | 11 | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 14 |
        15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 |
        29 | 30 | 31 | 127 | 48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 | 57 |
        97 | 98 | 99 | 100 | 101 | 102 | 103 | 104 | 105 | 106 | 107 | 108 |
        109 | 110 | 111 | 112 | 113 | 114 | 115 | 116 | 117 | 118 | 119 | 120
        | 121 | 122 | 33 | 34 | 35 | 36 | 37 | 38 | 39 | 40 | 41 | 42 | 43 |
        44 | 45 | 46 | 47 | 58 | 59 | 60 | 61 | 62 | 63 | 64 | 91 | 92 | 93 |
        94 | 95 | 96 | 123 | 124 | 125 | 126 | 65 | 66 | 67 | 68 | 69 | 70 |
        71 | 72 | 73 | 74 | 75 | 76 | 77 | 78 | 79 | 80 | 81 | 82 | 83 | 84 |
        85 | 86 | 87 | 88 | 89 | 90 => {
            return 1 as libc::c_int != 0
        }
        _ => { return 0 as libc::c_int != 0 }
    };
}
#[no_mangle]
#[inline]
#[linkage = "external"]
pub unsafe extern "C" fn c_isblank(mut c: libc::c_int) -> bool {
    return c == ' ' as i32 || c == '\t' as i32;
}
#[no_mangle]
#[inline]
#[linkage = "external"]
pub unsafe extern "C" fn c_iscntrl(mut c: libc::c_int) -> bool {
    match c {
        7 | 8 | 12 | 10 | 13 | 9 | 11 | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 14 | 15 |
        16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 |
        30 | 31 | 127 => {
            return 1 as libc::c_int != 0
        }
        _ => { return 0 as libc::c_int != 0 }
    };
}
#[no_mangle]
#[inline]
#[linkage = "external"]
pub unsafe extern "C" fn c_isdigit(mut c: libc::c_int) -> bool {
    match c {
        48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 | 57 => {
            return 1 as libc::c_int != 0
        }
        _ => { return 0 as libc::c_int != 0 }
    };
}
#[no_mangle]
#[inline]
#[linkage = "external"]
pub unsafe extern "C" fn c_isgraph(mut c: libc::c_int) -> bool {
    match c {
        48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 | 57 | 97 | 98 | 99 | 100 |
        101 | 102 | 103 | 104 | 105 | 106 | 107 | 108 | 109 | 110 | 111 | 112
        | 113 | 114 | 115 | 116 | 117 | 118 | 119 | 120 | 121 | 122 | 33 | 34
        | 35 | 36 | 37 | 38 | 39 | 40 | 41 | 42 | 43 | 44 | 45 | 46 | 47 | 58
        | 59 | 60 | 61 | 62 | 63 | 64 | 91 | 92 | 93 | 94 | 95 | 96 | 123 |
        124 | 125 | 126 | 65 | 66 | 67 | 68 | 69 | 70 | 71 | 72 | 73 | 74 | 75
        | 76 | 77 | 78 | 79 | 80 | 81 | 82 | 83 | 84 | 85 | 86 | 87 | 88 | 89
        | 90 => {
            return 1 as libc::c_int != 0
        }
        _ => { return 0 as libc::c_int != 0 }
    };
}
#[no_mangle]
#[inline]
#[linkage = "external"]
pub unsafe extern "C" fn c_islower(mut c: libc::c_int) -> bool {
    match c {
        97 | 98 | 99 | 100 | 101 | 102 | 103 | 104 | 105 | 106 | 107 | 108 |
        109 | 110 | 111 | 112 | 113 | 114 | 115 | 116 | 117 | 118 | 119 | 120
        | 121 | 122 => {
            return 1 as libc::c_int != 0
        }
        _ => { return 0 as libc::c_int != 0 }
    };
}
#[no_mangle]
#[inline]
#[linkage = "external"]
pub unsafe extern "C" fn c_isprint(mut c: libc::c_int) -> bool {
    match c {
        32 | 48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 | 57 | 97 | 98 | 99 |
        100 | 101 | 102 | 103 | 104 | 105 | 106 | 107 | 108 | 109 | 110 | 111
        | 112 | 113 | 114 | 115 | 116 | 117 | 118 | 119 | 120 | 121 | 122 | 33
        | 34 | 35 | 36 | 37 | 38 | 39 | 40 | 41 | 42 | 43 | 44 | 45 | 46 | 47
        | 58 | 59 | 60 | 61 | 62 | 63 | 64 | 91 | 92 | 93 | 94 | 95 | 96 | 123
        | 124 | 125 | 126 | 65 | 66 | 67 | 68 | 69 | 70 | 71 | 72 | 73 | 74 |
        75 | 76 | 77 | 78 | 79 | 80 | 81 | 82 | 83 | 84 | 85 | 86 | 87 | 88 |
        89 | 90 => {
            return 1 as libc::c_int != 0
        }
        _ => { return 0 as libc::c_int != 0 }
    };
}
#[no_mangle]
#[inline]
#[linkage = "external"]
pub unsafe extern "C" fn c_ispunct(mut c: libc::c_int) -> bool {
    match c {
        33 | 34 | 35 | 36 | 37 | 38 | 39 | 40 | 41 | 42 | 43 | 44 | 45 | 46 |
        47 | 58 | 59 | 60 | 61 | 62 | 63 | 64 | 91 | 92 | 93 | 94 | 95 | 96 |
        123 | 124 | 125 | 126 => {
            return 1 as libc::c_int != 0
        }
        _ => { return 0 as libc::c_int != 0 }
    };
}
#[no_mangle]
#[inline]
#[linkage = "external"]
pub unsafe extern "C" fn c_isspace(mut c: libc::c_int) -> bool {
    match c {
        32 | 9 | 10 | 11 | 12 | 13 => { return 1 as libc::c_int != 0 }
        _ => { return 0 as libc::c_int != 0 }
    };
}
#[no_mangle]
#[inline]
#[linkage = "external"]
pub unsafe extern "C" fn c_isupper(mut c: libc::c_int) -> bool {
    match c {
        65 | 66 | 67 | 68 | 69 | 70 | 71 | 72 | 73 | 74 | 75 | 76 | 77 | 78 |
        79 | 80 | 81 | 82 | 83 | 84 | 85 | 86 | 87 | 88 | 89 | 90 => {
            return 1 as libc::c_int != 0
        }
        _ => { return 0 as libc::c_int != 0 }
    };
}
#[no_mangle]
#[inline]
#[linkage = "external"]
pub unsafe extern "C" fn c_isxdigit(mut c: libc::c_int) -> bool {
    match c {
        48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 | 57 | 97 | 98 | 99 | 100 |
        101 | 102 | 65 | 66 | 67 | 68 | 69 | 70 => {
            return 1 as libc::c_int != 0
        }
        _ => { return 0 as libc::c_int != 0 }
    };
}
#[no_mangle]
#[inline]
#[linkage = "external"]
pub unsafe extern "C" fn c_tolower(mut c: libc::c_int) -> libc::c_int {
    match c {
        65 | 66 | 67 | 68 | 69 | 70 | 71 | 72 | 73 | 74 | 75 | 76 | 77 | 78 |
        79 | 80 | 81 | 82 | 83 | 84 | 85 | 86 | 87 | 88 | 89 | 90 => {
            return c - 'A' as i32 + 'a' as i32
        }
        _ => { return c }
    };
}
#[no_mangle]
#[inline]
#[linkage = "external"]
pub unsafe extern "C" fn c_toupper(mut c: libc::c_int) -> libc::c_int {
    match c {
        97 | 98 | 99 | 100 | 101 | 102 | 103 | 104 | 105 | 106 | 107 | 108 |
        109 | 110 | 111 | 112 | 113 | 114 | 115 | 116 | 117 | 118 | 119 | 120
        | 121 | 122 => {
            return c - 'a' as i32 + 'A' as i32
        }
        _ => { return c }
    };
}
/* Character handling in C locale.

   Copyright (C) 2003-2021 Free Software Foundation, Inc.

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
