use ::libc;
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stat {
    pub st_dev: __dev_t,
    pub st_ino: __ino_t,
    pub st_nlink: __nlink_t,
    pub st_mode: __mode_t,
    pub st_uid: __uid_t,
    pub st_gid: __gid_t,
    pub __pad0: libc::c_int,
    pub st_rdev: __dev_t,
    pub st_size: __off_t,
    pub st_blksize: __blksize_t,
    pub st_blocks: __blkcnt_t,
    pub st_atim: timespec,
    pub st_mtim: timespec,
    pub st_ctim: timespec,
    pub __glibc_reserved: [__syscall_slong_t; 3],
}
/* stat-related time functions.

   Copyright (C) 2005, 2007, 2009-2021 Free Software Foundation, Inc.

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
/* Written by Paul Eggert.  */
/* STAT_TIMESPEC (ST, ST_XTIM) is the ST_XTIM member for *ST of type
   struct timespec, if available.  If not, then STAT_TIMESPEC_NS (ST,
   ST_XTIM) is the nanosecond component of the ST_XTIM member for *ST,
   if available.  ST_XTIM can be st_atim, st_ctim, st_mtim, or st_birthtim
   for access, status change, data modification, or birth (creation)
   time respectively.

   These macros are private to stat-time.h.  */
/* Return the nanosecond component of *ST's access time.  */
/* Return the nanosecond component of *ST's status change time.  */
/* Return the nanosecond component of *ST's data modification time.  */
/* Return the nanosecond component of *ST's birth time.  */
/* Return *ST's access time.  */
/* Return *ST's status change time.  */
/* Return *ST's data modification time.  */
/* Return *ST's birth time, if available; otherwise return a value
   with tv_sec and tv_nsec both equal to -1.  */
/* Birth time is not supported.  */
/* If a stat-like function returned RESULT, normalize the timestamps
   in *ST, in case this platform suffers from the Solaris 11 bug where
   tv_nsec might be negative.  Return the adjusted RESULT, setting
   errno to EOVERFLOW if normalization overflowed.  This function
   is intended to be private to this .h file.  */
#[no_mangle]
#[inline]
pub unsafe extern "C" fn stat_time_normalize(mut result: libc::c_int,
                                             mut _st: *mut stat)
 -> libc::c_int {
    return result;
}
#[no_mangle]
#[inline]
pub unsafe extern "C" fn get_stat_birthtime(mut _st: *const stat) -> timespec {
    let mut t: timespec = timespec{tv_sec: 0, tv_nsec: 0,};
    t.tv_sec = -(1 as libc::c_int) as __time_t;
    t.tv_nsec = -(1 as libc::c_int) as __syscall_slong_t;
    return t;
}
#[no_mangle]
#[inline]
pub unsafe extern "C" fn get_stat_mtime(mut st: *const stat) -> timespec {
    return (*st).st_mtim;
}
#[no_mangle]
#[inline]
pub unsafe extern "C" fn get_stat_ctime(mut st: *const stat) -> timespec {
    return (*st).st_ctim;
}
#[no_mangle]
#[inline]
pub unsafe extern "C" fn get_stat_atime_ns(mut st: *const stat)
 -> libc::c_long {
    return (*st).st_atim.tv_nsec;
}
#[no_mangle]
#[inline]
pub unsafe extern "C" fn get_stat_ctime_ns(mut st: *const stat)
 -> libc::c_long {
    return (*st).st_ctim.tv_nsec;
}
#[no_mangle]
#[inline]
pub unsafe extern "C" fn get_stat_mtime_ns(mut st: *const stat)
 -> libc::c_long {
    return (*st).st_mtim.tv_nsec;
}
#[no_mangle]
#[inline]
pub unsafe extern "C" fn get_stat_birthtime_ns(mut _st: *const stat)
 -> libc::c_long {
    return 0 as libc::c_int as libc::c_long;
}
#[no_mangle]
#[inline]
pub unsafe extern "C" fn get_stat_atime(mut st: *const stat) -> timespec {
    return (*st).st_atim;
}
/* stat-related time functions.

   Copyright (C) 2012-2021 Free Software Foundation, Inc.

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
