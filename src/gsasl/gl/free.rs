use ::libc;
use libc::{__errno_location, free};

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
/* Make free() preserve errno.

   Copyright (C) 2003, 2006, 2009-2021 Free Software Foundation, Inc.

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
/* written by Paul Eggert */
/* Specification.  */
/* A function definition is only needed if HAVE_FREE_POSIX is not defined.  */

pub unsafe fn rpl_free(mut p: *mut libc::c_void) {
    let mut err: libc::c_int = *__errno_location();
    free(p);
    *__errno_location() = err;
}
