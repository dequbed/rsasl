use ::libc;
extern "C" {
    #[no_mangle]
    fn fcntl(__fd: libc::c_int, __cmd: libc::c_int, _: ...) -> libc::c_int;
    #[no_mangle]
    fn __errno_location() -> *mut libc::c_int;
    #[no_mangle]
    fn close(__fd: libc::c_int) -> libc::c_int;
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
/* Perform the specified ACTION on the file descriptor FD, possibly
   using the argument ARG further described below.  This replacement
   handles the following actions, and forwards all others on to the
   native fcntl.  An unrecognized ACTION returns -1 with errno set to
   EINVAL.

   F_DUPFD - duplicate FD, with int ARG being the minimum target fd.
   If successful, return the duplicate, which will be inheritable;
   otherwise return -1 and set errno.

   F_DUPFD_CLOEXEC - duplicate FD, with int ARG being the minimum
   target fd.  If successful, return the duplicate, which will not be
   inheritable; otherwise return -1 and set errno.

   F_GETFD - ARG need not be present.  If successful, return a
   non-negative value containing the descriptor flags of FD (only
   FD_CLOEXEC is portable, but other flags may be present); otherwise
   return -1 and set errno.  */
#[no_mangle]
pub unsafe extern "C" fn rpl_fcntl(mut fd: libc::c_int,
                                   mut action: libc::c_int, mut args: ...)
 -> libc::c_int 
 /* arg */
 {
    let mut arg: ::std::ffi::VaListImpl;
    let mut result: libc::c_int = -(1 as libc::c_int);
    arg = args.clone();
    match action {
        0 => {
            let mut target: libc::c_int = arg.arg::<libc::c_int>();
            result = rpl_fcntl_DUPFD(fd, target)
        }
        1030 => {
            let mut target_0: libc::c_int = arg.arg::<libc::c_int>();
            result = rpl_fcntl_DUPFD_CLOEXEC(fd, target_0)
        }
        _ => {
            /* !HAVE_FCNTL */
            /* Implementing F_SETFD on mingw is not trivial - there is no
         API for changing the O_NOINHERIT bit on an fd, and merely
         changing the HANDLE_FLAG_INHERIT bit on the underlying handle
         can lead to odd state.  It may be possible by duplicating the
         handle, using _open_osfhandle with the right flags, then
         using dup2 to move the duplicate onto the original, but that
         is not supported for now.  */
            let mut current_block_7: u64;
            match action {
                1 => {
                    /* POSIX */
                    current_block_7 = 2453145894527220284;
                }
                3 => { current_block_7 = 2453145894527220284; }
                1025 => { current_block_7 = 8892552165470518290; }
                9 => { current_block_7 = 16627166552877475723; }
                1032 => { current_block_7 = 15307301490765489955; }
                1034 => { current_block_7 = 13434239986635690899; }
                11 => { current_block_7 = 12424771829975051849; }
                1033 => {
                    /* Solaris */
                    /* macOS */
                    /* FreeBSD, AIX, Solaris */
                    /* FreeBSD, Solaris */
                    /* Solaris */
                    /* POSIX */
                    current_block_7 = 16249717445582779898;
                }
                0 => { current_block_7 = 16249717445582779898; }
                1030 => { current_block_7 = 14023188268186667002; }
                1026 => { current_block_7 = 6990334233067194278; }
                2 => { current_block_7 = 1435975074585630168; }
                4 => { current_block_7 = 286125667863391087; }
                8 => {
                    /* Linux */
                    current_block_7 = 13941801564986816563;
                }
                1031 => { current_block_7 = 13941801564986816563; }
                1024 | 10 => { current_block_7 = 2418221612711961498; }
                _ => {
                    /* Other actions take a pointer argument.  */
                    let mut p: *mut libc::c_void =
                        arg.arg::<*mut libc::c_void>();
                    result = fcntl(fd, action, p);
                    current_block_7 = 11307063007268554308;
                }
            }
            match current_block_7 {
                2453145894527220284 =>
                /* Linux */
                {
                    current_block_7 = 8892552165470518290;
                }
                16249717445582779898 =>
                /* POSIX */
                {
                    current_block_7 = 14023188268186667002;
                }
                13941801564986816563 =>
                /* macOS */
                /* Linux */
                {
                    current_block_7 = 2418221612711961498;
                }
                _ => { }
            }
            match current_block_7 {
                8892552165470518290 =>
                /* macOS */
                /* POSIX */
                {
                    current_block_7 = 16627166552877475723;
                }
                14023188268186667002 =>
                /* Solaris */
                /* Solaris */
                /* macOS */
                /* macOS */
                /* macOS */
                /* macOS */
                /* macOS */
                /* Linux */
                {
                    current_block_7 = 6990334233067194278;
                }
                _ => { }
            }
            match current_block_7 {
                16627166552877475723 =>
                /* Linux */
                {
                    current_block_7 = 15307301490765489955;
                }
                6990334233067194278 =>
                /* IRIX */
                /* IRIX */
                /* macOS */
                /* macOS */
                /* macOS */
                /* POSIX */
                {
                    current_block_7 = 1435975074585630168;
                }
                _ => { }
            }
            match current_block_7 {
                15307301490765489955 =>
                /* macOS */
                /* macOS */
                /* Linux */
                {
                    current_block_7 = 13434239986635690899;
                }
                1435975074585630168 =>
                /* POSIX */
                {
                    current_block_7 = 286125667863391087;
                }
                _ => { }
            }
            match current_block_7 {
                13434239986635690899 =>
                /* Linux */
                {
                    current_block_7 = 12424771829975051849;
                }
                286125667863391087 =>
                /* Linux */
                {
                    current_block_7 = 2418221612711961498;
                }
                _ => { }
            }
            match current_block_7 {
                12424771829975051849 =>
                /* macOS */
                /* macOS */
                /* NetBSD, HP-UX */
                /* macOS */
                /* macOS */
                /* macOS */
                /* macOS */
                /* macOS */
                /* POSIX */
                /* NetBSD */
                /* macOS */
                /* HP-UX */
                /* macOS */
                /* These actions take no argument.  */
                {
                    result = fcntl(fd, action)
                }
                2418221612711961498 =>
                /* macOS */
                /* POSIX */
                /* macOS */
                /* These actions take an 'int' argument.  */
                {
                    let mut x: libc::c_int = arg.arg::<libc::c_int>();
                    result = fcntl(fd, action, x)
                }
                _ => { }
            }
        }
    }
    return result;
}
/* Provide file descriptor control.

   Copyright (C) 2009-2021 Free Software Foundation, Inc.

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
/* Written by Eric Blake <ebb9@byu.net>.  */
/* Specification.  */
/* W32 */
/* Forward declarations, because we '#undef fcntl' in the middle of this
   compilation unit.  */
/* Our implementation of fcntl (fd, F_DUPFD, target).  */
unsafe extern "C" fn rpl_fcntl_DUPFD(mut fd: libc::c_int,
                                     mut target: libc::c_int) -> libc::c_int {
    let mut result: libc::c_int = 0;
    result = fcntl(fd, 0 as libc::c_int, target);
    return result;
}
// Initialized in run_static_initializers
static mut have_dupfd_cloexec: libc::c_int = 0;
/* Our implementation of fcntl (fd, F_DUPFD_CLOEXEC, target).  */
unsafe extern "C" fn rpl_fcntl_DUPFD_CLOEXEC(mut fd: libc::c_int,
                                             mut target: libc::c_int)
 -> libc::c_int {
    let mut result: libc::c_int = 0;
    /* HAVE_FCNTL */
    /* Try the system call first, if the headers claim it exists
     (that is, if GNULIB_defined_F_DUPFD_CLOEXEC is 0), since we
     may be running with a glibc that has the macro but with an
     older kernel that does not support it.  Cache the
     information on whether the system call really works, but
     avoid caching failure if the corresponding F_DUPFD fails
     for any reason.  0 = unknown, 1 = yes, -1 = no.  */
    if 0 as libc::c_int <= have_dupfd_cloexec {
        result = fcntl(fd, 1030 as libc::c_int, target);
        if 0 as libc::c_int <= result ||
               *__errno_location() != 22 as libc::c_int {
            have_dupfd_cloexec = 1 as libc::c_int
        } else {
            result = rpl_fcntl_DUPFD(fd, target);
            if result >= 0 as libc::c_int {
                have_dupfd_cloexec = -(1 as libc::c_int)
            }
        }
    } else { result = rpl_fcntl_DUPFD(fd, target) }
    if 0 as libc::c_int <= result && have_dupfd_cloexec == -(1 as libc::c_int)
       {
        let mut flags: libc::c_int = fcntl(result, 1 as libc::c_int);
        if flags < 0 as libc::c_int ||
               fcntl(result, 2 as libc::c_int, flags | 1 as libc::c_int) ==
                   -(1 as libc::c_int) {
            let mut saved_errno: libc::c_int = *__errno_location();
            close(result);
            *__errno_location() = saved_errno;
            result = -(1 as libc::c_int)
        }
    }
    /* HAVE_FCNTL */
    return result;
}
unsafe extern "C" fn run_static_initializers() {
    have_dupfd_cloexec =
        if 0 as libc::c_int != 0 {
            -(1 as libc::c_int)
        } else { 0 as libc::c_int }
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
