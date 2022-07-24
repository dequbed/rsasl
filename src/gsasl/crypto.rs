use crate::gsasl::gl::gc_gnulib::gc_nonce;
use libc::size_t;

pub unsafe fn gsasl_nonce(mut data: *mut libc::c_char, mut datalen: size_t) -> libc::c_int {
    return gc_nonce(data, datalen) as libc::c_int;
}