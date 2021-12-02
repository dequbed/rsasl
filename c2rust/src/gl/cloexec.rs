use ::libc;
extern "C" {
    /* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* Like <fcntl.h>, but with non-working flags defined to 0.

   Copyright (C) 2006-2021 Free Software Foundation, Inc.

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
    #[no_mangle]
    fn rpl_fcntl(fd: libc::c_int, action: libc::c_int, _: ...) -> libc::c_int;
}
/* cloexec.c - set or clear the close-on-exec descriptor flag

   Copyright (C) 2004, 2009-2021 Free Software Foundation, Inc.

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
/* Set the 'FD_CLOEXEC' flag of DESC if VALUE is true,
   or clear the flag if VALUE is false.
   Return 0 on success, or -1 on error with 'errno' set.

   Note that on MingW, this function does NOT protect DESC from being
   inherited into spawned children.  Instead, either use dup_cloexec
   followed by closing the original DESC, or use interfaces such as
   open or pipe2 that accept flags like O_CLOEXEC to create DESC
   non-inheritable in the first place.  */
/* cloexec.c - set or clear the close-on-exec descriptor flag

   Copyright (C) 1991, 2004-2006, 2009-2021 Free Software Foundation, Inc.

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
/* The code is taken from glibc/manual/llio.texi  */
/* Set the 'FD_CLOEXEC' flag of DESC if VALUE is true,
   or clear the flag if VALUE is false.
   Return 0 on success, or -1 on error with 'errno' set.

   Note that on MingW, this function does NOT protect DESC from being
   inherited into spawned children.  Instead, either use dup_cloexec
   followed by closing the original DESC, or use interfaces such as
   open or pipe2 that accept flags like O_CLOEXEC to create DESC
   non-inheritable in the first place.  */
#[no_mangle]
pub unsafe extern "C" fn set_cloexec_flag(mut desc: libc::c_int,
                                          mut value: bool) -> libc::c_int {
    let mut flags: libc::c_int =
        rpl_fcntl(desc, 1 as libc::c_int, 0 as libc::c_int);
    if 0 as libc::c_int <= flags {
        let mut newflags: libc::c_int =
            if value as libc::c_int != 0 {
                (flags) | 1 as libc::c_int
            } else { (flags) & !(1 as libc::c_int) };
        if flags == newflags ||
               rpl_fcntl(desc, 2 as libc::c_int, newflags) !=
                   -(1 as libc::c_int) {
            return 0 as libc::c_int
        }
    }
    return -(1 as libc::c_int);
    /* !F_SETFD */
    /* !F_SETFD */
}
/* Duplicates a file handle FD, while marking the copy to be closed
   prior to exec or spawn.  Returns -1 and sets errno if FD could not
   be duplicated.  */
/* Duplicates a file handle FD, while marking the copy to be closed
   prior to exec or spawn.  Returns -1 and sets errno if FD could not
   be duplicated.  */
#[no_mangle]
pub unsafe extern "C" fn dup_cloexec(mut fd: libc::c_int) -> libc::c_int {
    return rpl_fcntl(fd, 1030 as libc::c_int, 0 as libc::c_int);
}
