use ::libc;
use libc::size_t;
use crate::gsasl::consts::{GSASL_MALLOC_ERROR, GSASL_OK, GSASL_SASLPREP_ERROR};

extern "C" {
    fn strcpy(_: *mut libc::c_char, _: *const libc::c_char)
     -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> size_t;
    fn malloc(_: size_t) -> *mut libc::c_void;
}

pub type Gsasl_saslprep_flags = libc::c_uint;
pub const GSASL_ALLOW_UNASSIGNED: Gsasl_saslprep_flags = 1;

#[cfg(feature = "saslprep")]
pub unsafe fn gsasl_saslprep(mut in_0: *const libc::c_char,
                                        mut _flags: Gsasl_saslprep_flags,
                                        mut out: *mut *mut libc::c_char,
                                        mut _stringpreprc: *mut libc::c_int)
 -> libc::c_int {
    let mut i: size_t = 0;
    let mut inlen: size_t = strlen(in_0);
    i = 0 as libc::c_int as size_t;
    while i < inlen {
        if *in_0.offset(i as isize) as libc::c_int & 0x80 as libc::c_int != 0
           {
            *out = 0 as *mut libc::c_char;
            return GSASL_SASLPREP_ERROR as libc::c_int
        }
        i = i.wrapping_add(1)
    }
    *out =
        malloc(inlen.wrapping_add(1)) as
            *mut libc::c_char;
    if (*out).is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
    strcpy(*out, in_0);
    return GSASL_OK as libc::c_int;
}
